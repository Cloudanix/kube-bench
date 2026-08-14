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
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// compliantItem is the test_item every CBP check uses: is_compliant must equal true.
func compliantItem() *tests {
	return &tests{TestItems: []*testItem{
		{Flag: "is_compliant", Set: true, Compare: compare{Op: "eq", Value: "true"}},
	}}
}

func TestParseFailedResource(t *testing.T) {
	cases := []struct {
		name string
		row  string
		ok   bool
		want FailedResource
	}{
		{
			name: "pod with full metadata",
			row: "kind=Pod ns=default name=web-7d9f8b6c4-x2k4l uid=3f2a9c81 apiVersion=v1 " +
				"created=2026-07-20T10:03:11Z node=ip-10-0-1-23.ec2.internal " +
				"labels=app:web,app.kubernetes.io/name:web " +
				"owner=ReplicaSet/default/web-7d9f8b6c4/8c1ef2 " +
				"container=app image=nginx:latest privileged=true is_compliant=false",
			ok: true,
			want: FailedResource{
				Kind: "Pod", Namespace: "default", Name: "web-7d9f8b6c4-x2k4l",
				UID: "3f2a9c81", APIVersion: "v1",
				CreationTimestamp: "2026-07-20T10:03:11Z",
				Node:              "ip-10-0-1-23.ec2.internal",
				Labels:            map[string]string{"app": "web", "app.kubernetes.io/name": "web"},
				Owners: []ParentResource{
					{Kind: "ReplicaSet", Namespace: "default", Name: "web-7d9f8b6c4", UID: "8c1ef2"},
				},
				Parent: &ParentResource{Kind: "ReplicaSet", Namespace: "default", Name: "web-7d9f8b6c4", UID: "8c1ef2"},
				Attributes: []map[string]string{{
					"container": "app", "image": "nginx:latest", "privileged": "true",
				}},
			},
		},
		{
			name: "cluster-scoped emits no ns token",
			row:  "kind=Namespace name=dev uid=n-2 apiVersion=v1 enforce=none is_compliant=false",
			ok:   true,
			want: FailedResource{
				Kind: "Namespace", Name: "dev", UID: "n-2", APIVersion: "v1",
				Attributes: []map[string]string{{"enforce": "none"}},
			},
		},
		{
			name: "namespaced rolebinding keeps its namespace",
			row:  "kind=RoleBinding ns=ns-a name=edit uid=rb1 subject=system:anonymous is_compliant=false",
			ok:   true,
			want: FailedResource{
				Kind: "RoleBinding", Namespace: "ns-a", Name: "edit", UID: "rb1",
				Attributes: []map[string]string{{"subject": "system:anonymous"}},
			},
		},
		{
			name: "cluster-scoped owner has an empty namespace segment",
			row:  "kind=Pod ns=x name=y uid=z owner=Deployment//web/uid9 is_compliant=false",
			ok:   true,
			want: FailedResource{
				Kind: "Pod", Namespace: "x", Name: "y", UID: "z",
				Owners: []ParentResource{{Kind: "Deployment", Name: "web", UID: "uid9"}},
				Parent: &ParentResource{Kind: "Deployment", Name: "web", UID: "uid9"},
			},
		},
		{
			name: "repeated owner tokens keep the last as parent",
			row: "kind=Pod ns=x name=y uid=z " +
				"owner=ReplicaSet/x/web-rs/uid-rs owner=Deployment/x/web/uid-dep is_compliant=false",
			ok: true,
			want: FailedResource{
				Kind: "Pod", Namespace: "x", Name: "y", UID: "z",
				Owners: []ParentResource{
					{Kind: "ReplicaSet", Namespace: "x", Name: "web-rs", UID: "uid-rs"},
					{Kind: "Deployment", Namespace: "x", Name: "web", UID: "uid-dep"},
				},
				Parent: &ParentResource{Kind: "Deployment", Namespace: "x", Name: "web", UID: "uid-dep"},
			},
		},
		{
			name: "image digest ref survives the colon and at-sign",
			row:  "kind=Pod ns=p name=api uid=a1 container=api image=api@sha256:deadbeef is_compliant=false",
			ok:   true,
			want: FailedResource{
				Kind: "Pod", Namespace: "p", Name: "api", UID: "a1",
				Attributes: []map[string]string{{"container": "api", "image": "api@sha256:deadbeef"}},
			},
		},
		{
			name: "an audit may declare a cluster-scoped finding, which needs no name",
			row:  "kind=Cluster scope=cluster rbacMode=legacy is_compliant=false",
			ok:   true,
			want: FailedResource{
				Kind: "Cluster", Scope: ScopeCluster,
				Attributes: []map[string]string{{"rbacMode": "legacy"}},
			},
		},
		{
			name: "an unknown scope degrades to workload rather than reaching the backend",
			row:  "kind=Pod ns=x name=y scope=galaxy is_compliant=false",
			ok:   true,
			want: FailedResource{Kind: "Pod", Namespace: "x", Name: "y"},
		},
		// Rows that are not Kubernetes objects must produce nothing at all — this is what
		// keeps CIS/EKS file and process checks byte-identical.
		{name: "pass sentinel", row: "is_compliant=true"},
		{name: "process flag", row: "--anonymous-auth=false"},
		{name: "bare file mode", row: "644"},
		{name: "kind without name", row: "kind=Pod ns=default is_compliant=false"},
		// scope=cluster is what waives the name requirement; nothing else does.
		{name: "kind without name, node-scoped", row: "kind=Node scope=node is_compliant=false"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Every k8s object row is workload-scoped unless the case says otherwise.
			if c.ok && c.want.Scope == "" {
				c.want.Scope = ScopeWorkload
			}
			got, ok := parseFailedResource(c.row)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, c.ok, got)
			}
			if !ok {
				// A rejected row must not leak attributes either.
				if got.Attributes != nil {
					t.Errorf("rejected row still populated Attributes: %v", got.Attributes)
				}
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestExecuteCollectsFailedResources(t *testing.T) {
	rows := strings.Join([]string{
		"kind=Pod ns=default name=web uid=u1 container=app is_compliant=false",
		"kind=Pod ns=payments name=api uid=u2 container=api is_compliant=true",
		"kind=Pod ns=default name=web uid=u1 container=sidecar is_compliant=false",
	}, "\n")

	item := testItem{
		Flag: "is_compliant", Set: true,
		Compare:          compare{Op: "eq", Value: "true"},
		isMultipleOutput: true,
	}
	out := item.execute(rows)

	if out.testResult {
		t.Error("testResult = true, want false")
	}
	if out.actualResult != rows {
		t.Errorf("actualResult = %q, want the full blob", out.actualResult)
	}
	// Same pod, two different containers => ONE resource carrying both attribute sets, in
	// row order. The compliant row is skipped.
	if len(out.failedResources) != 1 {
		t.Fatalf("got %d failed resources, want 1: %+v", len(out.failedResources), out.failedResources)
	}
	fr := out.failedResources[0]
	if fr.Name != "web" || fr.UID != "u1" {
		t.Errorf("identity = %+v, want web/u1", fr)
	}
	if len(fr.Attributes) != 2 {
		t.Fatalf("got %d attribute sets, want 2: %v", len(fr.Attributes), fr.Attributes)
	}
	for i, want := range []string{"app", "sidecar"} {
		if got := fr.Attributes[i]["container"]; got != want {
			t.Errorf("attribute set %d container = %q, want %q", i, got, want)
		}
	}
}

// The whole point of the merge: one object failing a check several ways is one resource,
// never several rows sharing a (kind, name, uid).
func TestExecuteMergesRowsForTheSameObject(t *testing.T) {
	rows := strings.Join([]string{
		"kind=ClusterRoleBinding name=rogue-admin uid=crb-1 subject=ci subjectKind=ServiceAccount is_compliant=false",
		"kind=ClusterRoleBinding name=rogue-admin uid=crb-1 subject=system:anonymous subjectKind=User is_compliant=false",
		"kind=ClusterRoleBinding name=rogue-admin uid=crb-1 subject=system:unauthenticated subjectKind=Group is_compliant=false",
	}, "\n")

	item := testItem{
		Flag: "is_compliant", Set: true,
		Compare:          compare{Op: "eq", Value: "true"},
		isMultipleOutput: true,
	}
	out := item.execute(rows)

	if len(out.failedResources) != 1 {
		t.Fatalf("got %d failed resources, want 1: %+v", len(out.failedResources), out.failedResources)
	}
	if got := len(out.failedResources[0].Attributes); got != 3 {
		t.Errorf("got %d attribute sets, want 3: %v", got, out.failedResources[0].Attributes)
	}
}

func TestExecuteDedupesIdenticalRows(t *testing.T) {
	row := "kind=Pod ns=default name=web uid=u1 container=app is_compliant=false"
	item := testItem{
		Flag: "is_compliant", Set: true,
		Compare:          compare{Op: "eq", Value: "true"},
		isMultipleOutput: true,
	}
	out := item.execute(row + "\n" + row)
	if len(out.failedResources) != 1 {
		t.Fatalf("got %d failed resources, want 1: %+v", len(out.failedResources), out.failedResources)
	}
}

func TestExecuteAllPassCollectsNothing(t *testing.T) {
	rows := strings.Join([]string{
		"kind=Pod ns=default name=web uid=u1 is_compliant=true",
		"kind=Pod ns=payments name=api uid=u2 is_compliant=true",
	}, "\n")

	item := testItem{
		Flag: "is_compliant", Set: true,
		Compare:          compare{Op: "eq", Value: "true"},
		isMultipleOutput: true,
	}
	out := item.execute(rows)

	if !out.testResult {
		t.Error("testResult = false, want true")
	}
	// A kind= token on a passing row must never surface.
	if len(out.failedResources) != 0 {
		t.Errorf("got %+v, want no failed resources", out.failedResources)
	}
}

// Guards the behavior-preservation claim: the single-output path (every CIS / EKS file and
// process check) keeps the original early break and gains no failed resources.
func TestExecuteSingleOutputUnchanged(t *testing.T) {
	item := testItem{Flag: "--anonymous-auth", Set: true, Compare: compare{Op: "eq", Value: "false"}}

	pass := item.execute("--anonymous-auth=false")
	if !pass.testResult || len(pass.failedResources) != 0 {
		t.Errorf("pass: testResult=%v resources=%+v", pass.testResult, pass.failedResources)
	}

	fail := item.execute("--anonymous-auth=true")
	if fail.testResult || len(fail.failedResources) != 0 {
		t.Errorf("fail: testResult=%v resources=%+v", fail.testResult, fail.failedResources)
	}
}

func TestCheckRunPopulatesFailedResourcesJSON(t *testing.T) {
	c := &Check{
		ID: "C1.1", Scored: true, IsMultiple: true,
		Audit: "echo 'kind=Pod ns=default name=web uid=u1 owner=ReplicaSet/default/web-rs/u-rs container=app privileged=true is_compliant=false'\n" +
			"echo 'kind=Pod ns=payments name=api uid=u2 container=api is_compliant=true'",
		Tests: compliantItem(),
	}

	if state := c.run(); state != FAIL {
		t.Fatalf("state = %q, want FAIL", state)
	}
	if len(c.FailedResources) != 1 {
		t.Fatalf("got %d failed resources, want 1: %+v", len(c.FailedResources), c.FailedResources)
	}
	got := c.FailedResources[0]
	if got.Kind != "Pod" || got.Namespace != "default" || got.Name != "web" || got.UID != "u1" {
		t.Errorf("identity = %+v", got)
	}
	if got.Parent == nil || got.Parent.Kind != "ReplicaSet" || got.Parent.Name != "web-rs" {
		t.Errorf("parent = %+v, want ReplicaSet/web-rs", got.Parent)
	}
	if len(got.Attributes) != 1 || got.Attributes[0]["privileged"] != "true" {
		t.Errorf("attributes = %v, want privileged=true", got.Attributes)
	}

	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"failed_resources"`) {
		t.Errorf("marshaled check is missing failed_resources: %s", b)
	}
	if !strings.Contains(string(b), `"parent"`) {
		t.Errorf("marshaled check is missing parent: %s", b)
	}
}

// A file/process check must marshal exactly as before — omitempty keeps CIS/EKS output
// byte-identical.
func TestCheckRunOmitsFailedResourcesForFileChecks(t *testing.T) {
	c := &Check{
		ID: "1.1.1", Scored: true,
		Audit: "echo 644",
		Tests: &tests{TestItems: []*testItem{
			{Flag: "644", Set: true, Compare: compare{Op: "bitmask", Value: "600"}},
		}},
	}
	c.run()
	if len(c.FailedResources) != 0 {
		t.Errorf("got %+v, want none", c.FailedResources)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "failed_resources") {
		t.Errorf("file check emitted failed_resources: %s", b)
	}
}

// C2.1 / C2.4 / C4.1 emit only non-compliant rows, so a clean cluster produces empty audit
// output. The jq now emits a bare pass sentinel; assert that reads as PASS with no resources.
func TestEmptyAuditPassSentinel(t *testing.T) {
	c := &Check{
		ID: "C2.1", Scored: true, IsMultiple: true,
		Audit: "echo 'is_compliant=true'",
		Tests: compliantItem(),
	}
	if state := c.run(); state != PASS {
		t.Fatalf("state = %q, want PASS", state)
	}
	if len(c.FailedResources) != 0 {
		t.Errorf("got %+v, want none", c.FailedResources)
	}
}

