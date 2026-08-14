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

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func toUnstructured(t *testing.T, obj runtime.Object) *unstructured.Unstructured {
	t.Helper()
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		t.Fatal(err)
	}
	return &unstructured.Unstructured{Object: m}
}

func TestFillInventoryPodMatchesCollector(t *testing.T) {
	priv := true
	pod := &v1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "web", Namespace: "ns", UID: "uid-pod",
			Labels: map[string]string{"app": "web"},
			Annotations: map[string]string{
				"sidecar.istio.io/inject":                          "true",
				"kubectl.kubernetes.io/last-applied-configuration": "{}",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-rs", UID: "uid-rs",
			}},
		},
		Spec: v1.PodSpec{
			NodeName:           "n1",
			HostPID:            true,
			ServiceAccountName: "sa",
			Containers: []v1.Container{{
				Name: "app", Image: "nginx:1.25",
				SecurityContext: &v1.SecurityContext{Privileged: &priv},
			}},
		},
		Status: v1.PodStatus{PodIP: "10.0.0.1", Phase: v1.PodRunning},
	}
	rs := ParentResource{Kind: "ReplicaSet", Namespace: "ns", Name: "web-rs", UID: "uid-rs"}
	dep := ParentResource{Kind: "Deployment", Namespace: "ns", Name: "web", UID: "uid-dep"}
	fr := FailedResource{Kind: "Pod", Namespace: "ns", Name: "web", Scope: ScopeWorkload}
	store := &objectStore{
		lookup:      ownerLookup{ownerKey(rs): dep},
		objs:        map[string]*unstructured.Unstructured{ownerKey(ParentResource{Kind: "Pod", Namespace: "ns", Name: "web"}): toUnstructured(t, pod)},
		clusterName: "prod",
		clusterUID:  "cu1",
	}
	fr.fillInventory(store, 99)

	if fr.UID != "uid-pod" || fr.Node != "n1" || fr.PodIP != "10.0.0.1" || fr.Phase != "Running" {
		t.Errorf("identity/runtime = %+v", fr)
	}
	if !fr.HostPID || fr.ServiceAccountName != "sa" {
		t.Errorf("security = hostPID=%v sa=%q", fr.HostPID, fr.ServiceAccountName)
	}
	if fr.Annotations["sidecar.istio.io/inject"] != "true" {
		t.Errorf("annotations = %v", fr.Annotations)
	}
	if _, ok := fr.Annotations["kubectl.kubernetes.io/last-applied-configuration"]; ok {
		t.Error("last-applied-configuration must not leak")
	}
	if fr.Parent == nil || fr.Parent.Kind != "Deployment" || fr.Parent.Name != "web" {
		t.Errorf("parent = %+v, want Deployment/web", fr.Parent)
	}
	if len(fr.Owners) != 2 || fr.Owners[0].Kind != "ReplicaSet" {
		t.Errorf("owners = %+v", fr.Owners)
	}
	if len(fr.Containers) != 1 || fr.Containers[0].Image.Name != "library/nginx" || fr.Containers[0].Image.Version != "1.25" {
		t.Errorf("containers = %+v", fr.Containers)
	}
	if fr.Containers[0].SecurityContext == nil || fr.Containers[0].SecurityContext.Privileged == nil || !*fr.Containers[0].SecurityContext.Privileged {
		t.Errorf("container security = %+v", fr.Containers[0].SecurityContext)
	}
	if fr.Event != "create" || fr.EventTime != 99 || fr.ClusterName != "prod" || fr.ClusterUID != "cu1" {
		t.Errorf("event/cluster = event=%s time=%d name=%s uid=%s", fr.Event, fr.EventTime, fr.ClusterName, fr.ClusterUID)
	}
}

func TestFillInventoryNodeProviderID(t *testing.T) {
	node := &v1.Node{
		TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: map[string]string{"topology.kubernetes.io/region": "us-east-1"}},
		Spec:       v1.NodeSpec{ProviderID: "aws:///us-east-1a/i-0abc"},
	}
	fr := FailedResource{Kind: "Node", Name: "n1", Scope: ScopeNode}
	store := &objectStore{
		objs: map[string]*unstructured.Unstructured{
			ownerKey(ParentResource{Kind: "Node", Name: "n1"}): toUnstructured(t, node),
		},
	}
	fr.fillInventory(store, 1)
	if fr.NodeDetail == nil || fr.NodeDetail.ProviderID != "aws:///us-east-1a/i-0abc" || fr.NodeDetail.Region != "us-east-1" {
		t.Errorf("nodeDetail = %+v", fr.NodeDetail)
	}
}

func TestParseImage(t *testing.T) {
	img := parseImage("nginx:1.25")
	if img.Registry != "docker.io" || img.Name != "library/nginx" || img.Version != "1.25" {
		t.Errorf("got %+v", img)
	}
}

func TestWhitelistAnnotations(t *testing.T) {
	got := whitelistAnnotations(map[string]string{
		"sidecar.istio.io/inject": "true",
		"secret":                  "nope",
	})
	if len(got) != 1 || got["sidecar.istio.io/inject"] != "true" {
		t.Errorf("got %v", got)
	}
}
