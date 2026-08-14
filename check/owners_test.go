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
	"reflect"
	"testing"
)

func TestWalkOwnerChain(t *testing.T) {
	rs := ParentResource{Kind: "ReplicaSet", Namespace: "ns", Name: "web-rs", UID: "uid-rs"}
	dep := ParentResource{Kind: "Deployment", Namespace: "ns", Name: "web", UID: "uid-dep"}
	job := ParentResource{Kind: "Job", Namespace: "ns", Name: "backup", UID: "uid-job"}
	cj := ParentResource{Kind: "CronJob", Namespace: "ns", Name: "backup", UID: "uid-cj"}

	cases := []struct {
		name   string
		start  ParentResource
		lookup ownerLookup
		want   []ParentResource
	}{
		{
			name:   "ReplicaSet walks to Deployment",
			start:  rs,
			lookup: ownerLookup{ownerKey(rs): dep},
			want:   []ParentResource{rs, dep},
		},
		{
			name:   "Job walks to CronJob",
			start:  job,
			lookup: ownerLookup{ownerKey(job): cj},
			want:   []ParentResource{job, cj},
		},
		{
			name:   "DaemonSet with no further owner stays itself",
			start:  ParentResource{Kind: "DaemonSet", Namespace: "ns", Name: "agent", UID: "uid-ds"},
			lookup: ownerLookup{},
			want:   []ParentResource{{Kind: "DaemonSet", Namespace: "ns", Name: "agent", UID: "uid-ds"}},
		},
		{
			name:   "nil lookup returns the start",
			start:  rs,
			lookup: nil,
			want:   []ParentResource{rs},
		},
		{
			name:  "cycle stops without looping",
			start: rs,
			lookup: ownerLookup{
				ownerKey(rs):  dep,
				ownerKey(dep): rs,
			},
			want: []ParentResource{rs, dep},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := walkOwnerChain(c.start, c.lookup)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestWalkOwnerChainCapsLength(t *testing.T) {
	lookup := ownerLookup{}
	for i := 0; i < ownerChainLimit+5; i++ {
		cur := ParentResource{Kind: "X", Namespace: "ns", Name: string(rune('a' + i))}
		next := ParentResource{Kind: "X", Namespace: "ns", Name: string(rune('a' + i + 1))}
		lookup[ownerKey(cur)] = next
	}
	start := ParentResource{Kind: "X", Namespace: "ns", Name: "a"}
	got := walkOwnerChain(start, lookup)
	if len(got) != ownerChainLimit+1 { // start + 16 steps
		t.Fatalf("len = %d, want %d", len(got), ownerChainLimit+1)
	}
}

func TestResolveOwnersWalksToRoot(t *testing.T) {
	rs := ParentResource{Kind: "ReplicaSet", Namespace: "ns", Name: "web-rs", UID: "uid-rs"}
	dep := ParentResource{Kind: "Deployment", Namespace: "ns", Name: "web", UID: "uid-dep"}
	fr := FailedResource{
		Kind: "Pod", Namespace: "ns", Name: "web-pod", UID: "uid-pod",
		Owners: []ParentResource{rs},
		Parent: &rs,
	}
	fr.resolveOwners(ownerLookup{ownerKey(rs): dep})
	wantOwners := []ParentResource{rs, dep}
	if !reflect.DeepEqual(fr.Owners, wantOwners) {
		t.Errorf("owners = %+v, want %+v", fr.Owners, wantOwners)
	}
	if fr.Parent == nil || !reflect.DeepEqual(*fr.Parent, dep) {
		t.Errorf("parent = %+v, want %+v", fr.Parent, dep)
	}
}

func TestResolveOwnersKeepsParsedChainWhenLookupEmpty(t *testing.T) {
	rs := ParentResource{Kind: "ReplicaSet", Namespace: "ns", Name: "web-rs", UID: "uid-rs"}
	dep := ParentResource{Kind: "Deployment", Namespace: "ns", Name: "web", UID: "uid-dep"}
	fr := FailedResource{
		Kind: "Pod", Owners: []ParentResource{rs, dep}, Parent: &dep,
	}
	fr.resolveOwners(nil)
	if len(fr.Owners) != 2 {
		t.Fatalf("owners = %+v, want the parsed chain", fr.Owners)
	}
	if fr.Parent == nil || !reflect.DeepEqual(*fr.Parent, dep) {
		t.Errorf("parent = %+v, want Deployment", fr.Parent)
	}
}

func TestOwnerLookupFromListJSON(t *testing.T) {
	data := []byte(`{
		"kind": "List",
		"items": [
			{
				"kind": "ReplicaSet",
				"metadata": {
					"name": "web-rs",
					"namespace": "ns",
					"uid": "uid-rs",
					"ownerReferences": [
						{"kind": "Deployment", "name": "web", "uid": "uid-dep", "apiVersion": "apps/v1"}
					]
				}
			},
			{
				"kind": "Job",
				"metadata": {
					"name": "backup",
					"namespace": "ns",
					"ownerReferences": [
						{"kind": "CronJob", "name": "backup", "uid": "uid-cj"}
					]
				}
			},
			{
				"kind": "DaemonSet",
				"metadata": {"name": "agent", "namespace": "ns"}
			}
		]
	}`)
	lookup, err := ownerLookupFromListJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	gotRS, ok := lookup[ownerKey(ParentResource{Kind: "ReplicaSet", Namespace: "ns", Name: "web-rs"})]
	if !ok || gotRS.Kind != "Deployment" || gotRS.Name != "web" || gotRS.UID != "uid-dep" {
		t.Errorf("ReplicaSet owner = %+v", gotRS)
	}
	gotJob, ok := lookup[ownerKey(ParentResource{Kind: "Job", Namespace: "ns", Name: "backup"})]
	if !ok || gotJob.Kind != "CronJob" {
		t.Errorf("Job owner = %+v", gotJob)
	}
	if _, ok := lookup[ownerKey(ParentResource{Kind: "DaemonSet", Namespace: "ns", Name: "agent"})]; ok {
		t.Error("DaemonSet with no ownerReferences should be absent")
	}
}

func TestOwnerLookupFromListJSONRejectsGarbage(t *testing.T) {
	if _, err := ownerLookupFromListJSON([]byte(`not json`)); err == nil {
		t.Fatal("want error")
	}
}

type stubRunner struct {
	resources []FailedResource
}

func (s stubRunner) Run(c *Check) State {
	out := make([]FailedResource, len(s.resources))
	copy(out, s.resources)
	for i := range out {
		out[i].Owners = append([]ParentResource(nil), out[i].Owners...)
		if out[i].Parent != nil {
			p := *out[i].Parent
			out[i].Parent = &p
		}
	}
	c.FailedResources = out
	c.State = FAIL
	return FAIL
}

func policiesControls(t *testing.T, nChecks int) *Controls {
	t.Helper()
	in := []byte(`
---
type: "policies"
groups:
- id: "1"
  checks:
`)
	for i := 0; i < nChecks; i++ {
		in = append(in, []byte("  - id: C1."+string(rune('1'+i))+"\n    scored: true\n")...)
	}
	c, err := NewControls(POLICIES, in, "")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRunChecksResolvesParentFromLookup(t *testing.T) {
	rs := ParentResource{Kind: "ReplicaSet", Namespace: "ns", Name: "web-rs", UID: "uid-rs"}
	dep := ParentResource{Kind: "Deployment", Namespace: "ns", Name: "web", UID: "uid-dep"}
	orig := fetchObjectStore
	t.Cleanup(func() { fetchObjectStore = orig })
	fetchObjectStore = func() *objectStore {
		return &objectStore{lookup: ownerLookup{ownerKey(rs): dep}}
	}

	controls := policiesControls(t, 1)
	runner := stubRunner{resources: []FailedResource{{
		Kind: "Pod", Namespace: "ns", Name: "web-pod", UID: "uid-pod",
		Scope: ScopeWorkload, Owners: []ParentResource{rs}, Parent: &rs,
	}}}
	runAll := func(*Group, *Check) bool { return true }
	controls.RunChecks(runner, runAll, map[string]bool{})

	got := controls.Groups[0].Checks[0].FailedResources
	if len(got) != 1 {
		t.Fatalf("failed_resources = %+v", got)
	}
	if got[0].Parent == nil || !reflect.DeepEqual(*got[0].Parent, dep) {
		t.Errorf("parent = %+v, want Deployment web", got[0].Parent)
	}
	wantOwners := []ParentResource{rs, dep}
	if !reflect.DeepEqual(got[0].Owners, wantOwners) {
		t.Errorf("owners = %+v, want %+v", got[0].Owners, wantOwners)
	}
}

func TestRunChecksDoesNotFetchStoreWithoutResources(t *testing.T) {
	orig := fetchObjectStore
	t.Cleanup(func() { fetchObjectStore = orig })
	called := false
	fetchObjectStore = func() *objectStore {
		called = true
		return nil
	}

	controls := policiesControls(t, 1)
	runner := stubRunner{}
	controls.RunChecks(runner, func(*Group, *Check) bool { return true }, map[string]bool{})
	if called {
		t.Fatal("fetched inventory snapshot for a check with no failed resources")
	}
}

func TestRunChecksFetchesOwnerLookupOnce(t *testing.T) {
	rs := ParentResource{Kind: "ReplicaSet", Namespace: "ns", Name: "web-rs", UID: "uid-rs"}
	orig := fetchObjectStore
	t.Cleanup(func() { fetchObjectStore = orig })
	calls := 0
	fetchObjectStore = func() *objectStore {
		calls++
		return &objectStore{lookup: ownerLookup{}}
	}

	controls := policiesControls(t, 2)
	runner := stubRunner{resources: []FailedResource{{
		Kind: "Pod", Owners: []ParentResource{rs}, Parent: &rs, Scope: ScopeWorkload,
		Name: "p", UID: "u",
	}}}
	controls.RunChecks(runner, func(*Group, *Check) bool { return true }, map[string]bool{})
	if calls != 1 {
		t.Fatalf("fetchObjectStore calls = %d, want 1", calls)
	}
}
