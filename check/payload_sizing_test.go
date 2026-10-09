// Copyright © 2026 Cloudanix Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package check

// Payload sizing for the HTTP output. Not a correctness test: it builds a
// production-shaped scan (N pods through the real enrichPod path, 23 pod-wide
// checks, 80% failing, unique uids/IPs/container IDs so gzip cannot cheat) and
// reports legacy vs compact bytes, raw and gzip, so a change to FailedResource,
// the enrichment or the wire format can be sized before it reaches a customer.
// The production listener is Cloud Run behind Cloudflare and rejects HTTP/1
// bodies over 32 MiB; a 70-node EKS cluster (~1,500 pods) hit that in Oct 2026.
//
//	go test -run TestPayloadSizing -v ./check/                          # table
//	SIZING_PODS=1500,5000 go test -run TestPayloadSizing -v ./check/    # other sizes
//	SIZING_DUMP_DIR=/tmp/scan go test -run TestPayloadSizing ./check/   # + compact-<n>.json / legacy-<n>.json
//
// The dumps feed the misconfig e2e skill's offline check
// (cdx-k8s-misconfig-scanner-e2e/scripts/offline_check.py), which pushes them
// through the dummy backend's inflate+schema path and the real backend handler
// without a cluster. Skipped under -short so `make tests` (-race, 30s timeout)
// is unaffected.
//
// Reference numbers (2026-10-09, this generator):
//
//	 pods | legacy MB  legacy gz | compact MB compact gz
//	  500 |      37.4        3.7 |        4.8        0.7
//	 1500 |     112.3       10.9 |       14.3        2.0
//	 3000 |     224.6       21.7 |       28.6        4.0
//
// gzip alone is only ~10x: its 32 KB window cannot dedupe the per-check copies
// of a pod, which sit megabytes apart. Compaction is what makes the ratio hold.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	sizingImages     = 120
	sizingNodes      = 70
	sizingNamespaces = 25
	sizingFailRate   = 0.8
)

var sizingDefaultPods = []int{500, 1500, 3000}

// sizingChecks mirrors the pod-wide checks EKS 4.2.x + CBP C1.x run on a real
// cluster; each one lists every pod, so each failing pod is repeated per check.
var sizingChecks = []struct{ id, attr, val string }{
	{"C1.1", "privileged", "false"}, {"C1.2", "runAsNonRoot", "false"}, {"C1.3", "readOnlyRootFilesystem", "false"},
	{"C1.4", "allowPrivilegeEscalation", "true"}, {"C1.5", "capabilitiesDrop", ""}, {"C1.6", "hostPID", "false"},
	{"C1.7", "hostNetwork", "false"}, {"C1.8", "hostIPC", "false"}, {"C1.9", "seccompProfile", ""},
	{"C1.10", "image_tag", "latest"}, {"C1.11", "limits_cpu", ""}, {"C1.12", "limits_memory", ""},
	{"C1.13", "livenessProbe", "false"}, {"C1.14", "readinessProbe", "false"}, {"C1.15", "automountServiceAccountToken", "true"},
	{"C1.16", "hostPathVolume", "false"}, {"4.2.1", "privileged", "false"}, {"4.2.2", "hostPID", "false"},
	{"4.2.3", "hostIPC", "false"}, {"4.2.4", "hostNetwork", "false"}, {"4.2.5", "allowPrivilegeEscalation", "true"},
	{"4.2.6", "runAsNonRoot", "false"}, {"4.2.7", "capabilitiesAdd", "NET_RAW"},
}

type sizingRand struct{ *rand.Rand }

func (r sizingRand) hex(n int) string {
	const digits = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = digits[r.Intn(16)]
	}
	return string(b)
}

func (r sizingRand) uuid() string {
	return r.hex(8) + "-" + r.hex(4) + "-4" + r.hex(3) + "-" + r.hex(4) + "-" + r.hex(12)
}

type sizingPod struct {
	fr  FailedResource
	row string // the audit line kube-bench's jq would print for this pod
}

// sizingPods builds n pods the way a cluster really looks: 120 distinct images,
// 70 nodes, 25 namespaces, two containers each, ReplicaSet->Deployment owners,
// and per-pod unique identifiers. Enrichment goes through the real
// applyInventoryIdentity + enrichPod so a field added there is sized here.
func sizingPods(t *testing.T, n int) []sizingPod {
	t.Helper()
	r := sizingRand{rand.New(rand.NewSource(42))}
	imageDigest := make([]string, sizingImages)
	deployUID := make([]string, sizingImages)
	tplHash := make([]string, sizingImages)
	for i := range imageDigest {
		imageDigest[i] = "sha256:" + r.hex(64)
		deployUID[i] = r.uuid()
		tplHash[i] = r.hex(10)
	}
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	pods := make([]sizingPod, 0, n)
	for i := 0; i < n; i++ {
		svc := i % sizingImages
		ns := fmt.Sprintf("ns-%d", i%sizingNamespaces)
		rsName := fmt.Sprintf("svc-%d-%s", svc, tplHash[svc])
		name := rsName + "-" + r.hex(5)
		node := fmt.Sprintf("ip-10-0-%d-%d.ec2.internal", i%sizingNodes, 10+i%sizingNodes)
		uid := r.uuid()
		priv, nonRoot, ro, ape := false, false, false, true
		var runAs int64 = 1000
		created := metav1.NewTime(base.Add(time.Duration(i) * 97 * time.Second))
		started := metav1.NewTime(created.Add(12 * time.Second))
		ip := fmt.Sprintf("10.%d.%d.%d", 1+i/65536, (i/256)%256, i%256)
		image := fmt.Sprintf("123456789012.dkr.ecr.us-east-1.amazonaws.com/org/svc-%d", svc)
		secCtx := func() *v1.SecurityContext {
			return &v1.SecurityContext{Privileged: &priv, RunAsNonRoot: &nonRoot, ReadOnlyRootFilesystem: &ro, AllowPrivilegeEscalation: &ape}
		}
		pod := &v1.Pod{
			TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: ns, UID: types.UID(uid), GenerateName: rsName + "-",
				ResourceVersion: strconv.Itoa(48000000 + i*37), CreationTimestamp: created,
				Labels: map[string]string{
					"app": fmt.Sprintf("svc-%d", svc), "pod-template-hash": tplHash[svc],
					"app.kubernetes.io/name": fmt.Sprintf("svc-%d", svc), "team": fmt.Sprintf("team-%d", svc%9),
					"environment": "production", "version": fmt.Sprintf("v1.%d.%d", svc%7, svc%13),
				},
				Annotations: map[string]string{
					"prometheus.io/scrape": "true", "prometheus.io/port": "9090",
					"kubectl.kubernetes.io/last-applied-configuration": strings.Repeat("x", 900), // whitelisted away
				},
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rsName, UID: types.UID(r.uuid())}},
			},
			Spec: v1.PodSpec{
				NodeName: node, ServiceAccountName: fmt.Sprintf("svc-%d-sa", svc), SchedulerName: "default-scheduler",
				PriorityClassName: "default", NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
				SecurityContext: &v1.PodSecurityContext{RunAsUser: &runAs, FSGroup: &runAs},
				Tolerations: []v1.Toleration{
					{Key: "node.kubernetes.io/not-ready", Operator: "Exists", Effect: "NoExecute"},
					{Key: "node.kubernetes.io/unreachable", Operator: "Exists", Effect: "NoExecute"},
					{Key: "dedicated", Operator: "Equal", Value: "workers", Effect: "NoSchedule"},
				},
				Volumes: []v1.Volume{
					{Name: "cfg", VolumeSource: v1.VolumeSource{ConfigMap: &v1.ConfigMapVolumeSource{LocalObjectReference: v1.LocalObjectReference{Name: fmt.Sprintf("svc-%d-config", svc)}}}},
					{Name: "tls", VolumeSource: v1.VolumeSource{Secret: &v1.SecretVolumeSource{SecretName: fmt.Sprintf("svc-%d-tls", svc)}}},
				},
				Containers: []v1.Container{
					{
						Name: "app", Image: fmt.Sprintf("%s:v1.%d.%d", image, svc%7, svc%13),
						Ports:           []v1.ContainerPort{{Name: "http", ContainerPort: 8080, Protocol: "TCP"}, {Name: "metrics", ContainerPort: 9090, Protocol: "TCP"}},
						SecurityContext: secCtx(),
						Resources: v1.ResourceRequirements{
							Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("250m"), v1.ResourceMemory: resource.MustParse("512Mi")},
							Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("1"), v1.ResourceMemory: resource.MustParse("1Gi")},
						},
						EnvFrom: []v1.EnvFromSource{{ConfigMapRef: &v1.ConfigMapEnvSource{LocalObjectReference: v1.LocalObjectReference{Name: fmt.Sprintf("svc-%d-env", svc)}}}},
						Env:     []v1.EnvVar{{Name: "DB_PASSWORD", ValueFrom: &v1.EnvVarSource{SecretKeyRef: &v1.SecretKeySelector{LocalObjectReference: v1.LocalObjectReference{Name: fmt.Sprintf("svc-%d-db", svc)}, Key: "password"}}}},
					},
					{
						Name: "istio-proxy", Image: "docker.io/istio/proxyv2:1.22.3",
						Ports:           []v1.ContainerPort{{Name: "http-envoy-prom", ContainerPort: 15090, Protocol: "TCP"}},
						SecurityContext: secCtx(),
						Resources: v1.ResourceRequirements{
							Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("100m"), v1.ResourceMemory: resource.MustParse("128Mi")},
							Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("2"), v1.ResourceMemory: resource.MustParse("1Gi")},
						},
					},
				},
			},
			Status: v1.PodStatus{
				Phase: v1.PodRunning, QOSClass: v1.PodQOSBurstable, StartTime: &started,
				PodIP: ip, HostIP: fmt.Sprintf("10.0.%d.%d", i%sizingNodes, 10+i%sizingNodes), PodIPs: []v1.PodIP{{IP: ip}},
				Conditions: []v1.PodCondition{
					{Type: v1.PodInitialized, Status: v1.ConditionTrue, LastTransitionTime: started},
					{Type: v1.PodReady, Status: v1.ConditionTrue, LastTransitionTime: started},
					{Type: v1.ContainersReady, Status: v1.ConditionTrue, LastTransitionTime: started},
					{Type: v1.PodScheduled, Status: v1.ConditionTrue, LastTransitionTime: created},
					{Type: "PodReadyToStartContainers", Status: v1.ConditionTrue, LastTransitionTime: started},
				},
				ContainerStatuses: []v1.ContainerStatus{
					{
						Name: "app", Ready: true, RestartCount: int32(i % 3), ContainerID: "containerd://" + r.hex(64),
						ImageID: image + "@" + imageDigest[svc],
						State:   v1.ContainerState{Running: &v1.ContainerStateRunning{StartedAt: started}},
					},
					{
						Name: "istio-proxy", Ready: true, ContainerID: "containerd://" + r.hex(64),
						ImageID: "docker.io/istio/proxyv2@" + imageDigest[0],
						State:   v1.ContainerState{Running: &v1.ContainerStateRunning{StartedAt: started}},
					},
				},
			},
		}
		obj := toUnstructured(t, pod)
		fr := FailedResource{Kind: "Pod", Scope: ScopeWorkload, Namespace: ns, Name: name}
		applyInventoryIdentity(&fr, obj, "arn:aws:eks:us-east-1:123456789012:cluster/prod-eks", "c0ffee00-"+r.hex(4), 1760000000)
		fr.Owners = []ParentResource{
			{Kind: "ReplicaSet", Namespace: ns, Name: rsName, UID: string(pod.OwnerReferences[0].UID), APIVersion: "apps/v1"},
			{Kind: "Deployment", Namespace: ns, Name: fmt.Sprintf("svc-%d", svc), UID: deployUID[svc], APIVersion: "apps/v1"},
		}
		fr.setParentFromOwners()
		enrichPod(&fr, obj)
		pods = append(pods, sizingPod{fr: fr, row: fmt.Sprintf("kind=Pod namespace=%s name=%s uid=%s container=app", ns, name, uid)})
	}
	return pods
}

// sizingControls lays the pods out the way RunChecks does: every check that a pod
// fails gets its own copy of the enriched resource plus its audit row.
func sizingControls(pods []sizingPod) []*Controls {
	group := &Group{ID: "5.2", Text: "Pod Security Standards"}
	for ci, sc := range sizingChecks {
		c := &Check{
			ID: sc.id, Text: "Minimize the admission of containers with " + sc.attr + " (Automated)",
			Audit:  "kubectl get pods --all-namespaces -o json | jq -r '.items[] | ... | \"kind=Pod namespace=\\(.metadata.namespace) name=\\(.metadata.name) uid=\\(.metadata.uid) container=\\(.name) " + sc.attr + "=\\(.v) is_compliant=\\(.ok)\"'",
			Scored: true, State: FAIL, Severity: "high",
			Remediation:    "Create a PodSecurityPolicy or admission policy that denies " + sc.attr + " and redeploy the affected workloads with a compliant securityContext. See the CIS Kubernetes Benchmark section 5.2 for the full rationale and remediation steps.",
			TestInfo:       []string{"Create a PodSecurityPolicy or admission policy that denies " + sc.attr + "."},
			ExpectedResult: "'is_compliant' is equal to 'true'",
		}
		var actual strings.Builder
		for pi, p := range pods {
			if float64((pi*31+ci*17)%100) >= sizingFailRate*100 {
				continue
			}
			fr := p.fr
			fr.Attributes = []map[string]string{{"container": "app", sc.attr: sc.val, "is_compliant": "false"}}
			c.FailedResources = append(c.FailedResources, fr)
			actual.WriteString(p.row + " " + sc.attr + "=" + sc.val + " is_compliant=false\n")
		}
		c.ActualValue = actual.String()
		group.Checks = append(group.Checks, c)
		group.Fail++
	}
	return []*Controls{{ID: "5", Version: "cloudanix-1.0", Text: "Kubernetes Policies", Type: POLICIES, Groups: []*Group{group}}}
}

func gzipLen(b []byte) int {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Len()
}

func sizingPodCounts(t *testing.T) []int {
	t.Helper()
	raw := os.Getenv("SIZING_PODS")
	if raw == "" {
		return sizingDefaultPods
	}
	var counts []int
	for _, s := range strings.Split(raw, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || n <= 0 {
			t.Fatalf("SIZING_PODS: %q is not a positive integer", s)
		}
		counts = append(counts, n)
	}
	return counts
}

func TestPayloadSizing(t *testing.T) {
	if testing.Short() {
		t.Skip("sizing only; run without -short")
	}
	dumpDir := os.Getenv("SIZING_DUMP_DIR")
	mb := func(n int) string { return fmt.Sprintf("%.1f", float64(n)/1024/1024) }

	t.Logf("%6s | %10s %10s | %10s %10s | %6s %6s", "pods", "legacy MB", "legacy gz", "compact MB", "compact gz", "raw x", "wire x")
	for _, n := range sizingPodCounts(t) {
		pods := sizingPods(t, n)
		legacy, err := json.Marshal(sizingControls(pods))
		if err != nil {
			t.Fatal(err)
		}
		controls := sizingControls(pods)
		table := CompactResources(controls)
		compact, err := json.Marshal(struct {
			Controls  []*Controls               `json:"controls"`
			Resources map[string]FailedResource `json:"resources"`
		}{controls, table})
		if err != nil {
			t.Fatal(err)
		}
		if len(table) != n {
			t.Errorf("%d pods: table has %d entries, want one per pod", n, len(table))
		}
		lg, cg := gzipLen(legacy), gzipLen(compact)
		t.Logf("%6d | %10s %10s | %10s %10s | %6.1f %6.1f", n, mb(len(legacy)), mb(lg), mb(len(compact)), mb(cg),
			float64(len(legacy))/float64(len(compact)), float64(len(legacy))/float64(cg))
		if dumpDir == "" {
			continue
		}
		for name, b := range map[string][]byte{"compact": compact, "legacy": legacy} {
			p := filepath.Join(dumpDir, fmt.Sprintf("%s-%d.json", name, n))
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Logf("wrote %s (%d bytes)", p, len(b))
		}
	}
	one, _ := json.Marshal(sizingPods(t, 1)[0].fr)
	t.Logf("one enriched pod entry = %d bytes", len(one))
}
