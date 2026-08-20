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
	"errors"
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// unstructuredObj builds a minimal unstructured object of the given kind,
// with an optional single owner reference, for objectStore.objs fixtures.
func unstructuredObj(kind, ns, name, uid string, owner *ParentResource) *unstructured.Unstructured {
	meta := map[string]interface{}{"name": name}
	if ns != "" {
		meta["namespace"] = ns
	}
	if uid != "" {
		meta["uid"] = uid
	}
	if owner != nil {
		meta["ownerReferences"] = []interface{}{
			map[string]interface{}{
				"kind":       owner.Kind,
				"name":       owner.Name,
				"uid":        owner.UID,
				"apiVersion": owner.APIVersion,
			},
		}
	}
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"kind":     kind,
		"metadata": meta,
	}}
}

// storeWithObjs builds an objectStore whose cache is pre-seeded directly, so
// tests never exec a real kubectl.
func storeWithObjs(objs map[string]*unstructured.Unstructured) *objectStore {
	return &objectStore{objs: objs, misses: map[string]bool{}}
}

func TestWalkOwnerChain(t *testing.T) {
	rs := ParentResource{Kind: "ReplicaSet", Namespace: "ns", Name: "web-rs", UID: "uid-rs"}
	dep := ParentResource{Kind: "Deployment", Namespace: "ns", Name: "web", UID: "uid-dep"}
	job := ParentResource{Kind: "Job", Namespace: "ns", Name: "backup", UID: "uid-job"}
	cj := ParentResource{Kind: "CronJob", Namespace: "ns", Name: "backup", UID: "uid-cj"}

	cases := []struct {
		name  string
		start ParentResource
		store *objectStore
		want  []ParentResource
	}{
		{
			name:  "ReplicaSet walks to Deployment",
			start: rs,
			store: storeWithObjs(map[string]*unstructured.Unstructured{
				ownerKey(rs): unstructuredObj("ReplicaSet", "ns", "web-rs", "uid-rs", &dep),
			}),
			want: []ParentResource{rs, dep},
		},
		{
			name:  "Job walks to CronJob",
			start: job,
			store: storeWithObjs(map[string]*unstructured.Unstructured{
				ownerKey(job): unstructuredObj("Job", "ns", "backup", "uid-job", &cj),
			}),
			want: []ParentResource{job, cj},
		},
		{
			name:  "DaemonSet with no further owner stays itself",
			start: ParentResource{Kind: "DaemonSet", Namespace: "ns", Name: "agent", UID: "uid-ds"},
			store: storeWithObjs(map[string]*unstructured.Unstructured{}),
			want:  []ParentResource{{Kind: "DaemonSet", Namespace: "ns", Name: "agent", UID: "uid-ds"}},
		},
		{
			name:  "nil store returns the start",
			start: rs,
			store: nil,
			want:  []ParentResource{rs},
		},
		{
			name:  "cycle stops without looping",
			start: rs,
			store: storeWithObjs(map[string]*unstructured.Unstructured{
				ownerKey(rs):  unstructuredObj("ReplicaSet", "ns", "web-rs", "uid-rs", &dep),
				ownerKey(dep): unstructuredObj("Deployment", "ns", "web", "uid-dep", &rs),
			}),
			want: []ParentResource{rs, dep},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := walkOwnerChain(c.store, c.start)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestWalkOwnerChainCapsLength(t *testing.T) {
	objs := map[string]*unstructured.Unstructured{}
	for i := 0; i < ownerChainLimit+5; i++ {
		cur := ParentResource{Kind: "X", Namespace: "ns", Name: string(rune('a' + i))}
		next := ParentResource{Kind: "X", Namespace: "ns", Name: string(rune('a' + i + 1))}
		objs[ownerKey(cur)] = unstructuredObj("X", "ns", cur.Name, "", &next)
	}
	store := storeWithObjs(objs)
	start := ParentResource{Kind: "X", Namespace: "ns", Name: "a"}
	got := walkOwnerChain(store, start)
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
	store := storeWithObjs(map[string]*unstructured.Unstructured{
		ownerKey(rs): unstructuredObj("ReplicaSet", "ns", "web-rs", "uid-rs", &dep),
	})
	fr.resolveOwners(store)
	wantOwners := []ParentResource{rs, dep}
	if !reflect.DeepEqual(fr.Owners, wantOwners) {
		t.Errorf("owners = %+v, want %+v", fr.Owners, wantOwners)
	}
	if fr.Parent == nil || !reflect.DeepEqual(*fr.Parent, dep) {
		t.Errorf("parent = %+v, want %+v", fr.Parent, dep)
	}
}

func TestResolveOwnersKeepsParsedChainWhenStoreCantExtend(t *testing.T) {
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

func TestObjectStoreGetCachesFetchByKey(t *testing.T) {
	orig := fetchOne
	t.Cleanup(func() { fetchOne = orig })
	calls := 0
	fetchOne = func(resource, ns, name string, clusterScoped bool) ([]byte, error) {
		calls++
		if resource != "replicasets" || ns != "ns" || name != "web-rs" || clusterScoped {
			t.Errorf("fetchOne called with resource=%q ns=%q name=%q clusterScoped=%v", resource, ns, name, clusterScoped)
		}
		return []byte(`{"kind":"ReplicaSet","metadata":{"name":"web-rs","namespace":"ns"}}`), nil
	}

	store := newObjectStore()
	for i := 0; i < 3; i++ {
		o := store.get("ReplicaSet", "ns", "web-rs")
		if o == nil {
			t.Fatal("get returned nil")
		}
	}
	if calls != 1 {
		t.Fatalf("fetchOne calls = %d, want 1", calls)
	}
}

func TestObjectStoreGetCachesMissWithoutRefetch(t *testing.T) {
	orig := fetchOne
	t.Cleanup(func() { fetchOne = orig })
	calls := 0
	fetchOne = func(resource, ns, name string, clusterScoped bool) ([]byte, error) {
		calls++
		return nil, errors.New("not found")
	}

	store := newObjectStore()
	if o := store.get("Pod", "ns", "gone"); o != nil {
		t.Fatalf("get = %+v, want nil", o)
	}
	if o := store.get("Pod", "ns", "gone"); o != nil {
		t.Fatalf("get = %+v, want nil", o)
	}
	if calls != 1 {
		t.Fatalf("fetchOne calls = %d, want 1", calls)
	}
}

func TestObjectStoreGetUnknownKindSkipsFetch(t *testing.T) {
	orig := fetchOne
	t.Cleanup(func() { fetchOne = orig })
	called := false
	fetchOne = func(resource, ns, name string, clusterScoped bool) ([]byte, error) {
		called = true
		return nil, errors.New("should not be called")
	}

	store := newObjectStore()
	if o := store.get("EndpointSlice", "ns", "x"); o != nil {
		t.Fatalf("get = %+v, want nil for an unmapped kind", o)
	}
	if called {
		t.Fatal("fetchOne called for a kind kube-bench has no resource mapping for")
	}
}

func TestObjectStoreGetClusterScopedOmitsNamespace(t *testing.T) {
	orig := fetchOne
	t.Cleanup(func() { fetchOne = orig })
	var gotNS string
	var gotClusterScoped bool
	fetchOne = func(resource, ns, name string, clusterScoped bool) ([]byte, error) {
		gotNS, gotClusterScoped = ns, clusterScoped
		return []byte(`{"kind":"Node","metadata":{"name":"n1"}}`), nil
	}

	store := newObjectStore()
	store.get("Node", "", "n1")
	if !gotClusterScoped {
		t.Error("Node should be requested as cluster-scoped")
	}
	if gotNS != "" {
		t.Errorf("namespace = %q, want empty for a cluster-scoped kind", gotNS)
	}
}

func TestGetClusterUIDFetchesKubeSystemOnceAndCaches(t *testing.T) {
	orig := fetchOne
	t.Cleanup(func() { fetchOne = orig })
	calls := 0
	fetchOne = func(resource, ns, name string, clusterScoped bool) ([]byte, error) {
		calls++
		if resource != "namespaces" || name != "kube-system" {
			t.Errorf("fetchOne called with resource=%q name=%q, want namespaces/kube-system", resource, name)
		}
		return []byte(`{"kind":"Namespace","metadata":{"name":"kube-system","uid":"cluster-uid-1"}}`), nil
	}

	store := newObjectStore()
	if got := store.getClusterUID(); got != "cluster-uid-1" {
		t.Fatalf("getClusterUID = %q, want cluster-uid-1", got)
	}
	if got := store.getClusterUID(); got != "cluster-uid-1" {
		t.Fatalf("getClusterUID (2nd call) = %q, want cluster-uid-1", got)
	}
	if calls != 1 {
		t.Fatalf("fetchOne calls = %d, want 1", calls)
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

func TestRunChecksResolvesParentFromFetchedOwner(t *testing.T) {
	rs := ParentResource{Kind: "ReplicaSet", Namespace: "ns", Name: "web-rs", UID: "uid-rs"}
	dep := ParentResource{Kind: "Deployment", Namespace: "ns", Name: "web", UID: "uid-dep"}
	resetObjectStoreCache()
	t.Cleanup(resetObjectStoreCache)
	objectStoreOnce.Do(func() {
		cachedObjectStore = storeWithObjs(map[string]*unstructured.Unstructured{
			ownerKey(rs): unstructuredObj("ReplicaSet", "ns", "web-rs", "uid-rs", &dep),
		})
	})

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

func TestRunChecksDoesNotFetchWithoutFailedResources(t *testing.T) {
	orig := fetchOne
	resetObjectStoreCache()
	t.Cleanup(func() { fetchOne = orig; resetObjectStoreCache() })
	called := false
	fetchOne = func(resource, ns, name string, clusterScoped bool) ([]byte, error) {
		called = true
		return nil, errors.New("should not be called")
	}

	controls := policiesControls(t, 1)
	runner := stubRunner{}
	controls.RunChecks(runner, func(*Group, *Check) bool { return true }, map[string]bool{})
	if called {
		t.Fatal("fetched an object for a check with no failed resources")
	}
}

// countingFetchOne returns a fetchOne stub that records how many times each
// distinct (resource, name) pair was actually exec'd, and a valid canned
// object for any request (kind is irrelevant to the caching behavior under
// test).
func countingFetchOne(t *testing.T) (fn func(resource, ns, name string, clusterScoped bool) ([]byte, error), calls map[string]int) {
	t.Helper()
	calls = map[string]int{}
	fn = func(resource, ns, name string, clusterScoped bool) ([]byte, error) {
		calls[resource+"/"+ns+"/"+name]++
		return []byte(`{"kind":"ReplicaSet","metadata":{"name":"` + name + `","namespace":"` + ns + `"}}`), nil
	}
	return fn, calls
}

// TestObjectStoreDeduplicatesFetchesWithinRunChecks is the narrow-fetch perf
// property: many checks whose failed resources share one parent (or resolve
// to the same object, like the one-time cluster UID lookup) only pay for that
// object's kubectl get once, no matter how many checks reference it.
func TestObjectStoreDeduplicatesFetchesWithinRunChecks(t *testing.T) {
	rs := ParentResource{Kind: "ReplicaSet", Namespace: "ns", Name: "web-rs", UID: "uid-rs"}
	orig := fetchOne
	resetObjectStoreCache()
	t.Cleanup(func() { fetchOne = orig; resetObjectStoreCache() })
	fn, calls := countingFetchOne(t)
	fetchOne = fn

	controls := policiesControls(t, 2)
	runner := stubRunner{resources: []FailedResource{{
		Kind: "Pod", Owners: []ParentResource{rs}, Parent: &rs, Scope: ScopeWorkload,
		Name: "p", UID: "u", Namespace: "ns",
	}}}
	controls.RunChecks(runner, func(*Group, *Check) bool { return true }, map[string]bool{})

	// Both checks report the identical Pod, so every distinct object kube-bench
	// had to fetch (the Pod itself, its ReplicaSet owner, the one-time
	// kube-system lookup for cluster UID) must appear exactly once, not once
	// per check.
	for key, n := range calls {
		if n != 1 {
			t.Errorf("fetchOne calls for %s = %d, want 1", key, n)
		}
	}
	if len(calls) == 0 {
		t.Fatal("fetchOne was never called")
	}
}

// TestObjectStoreCachedAcrossRunChecks is the actual perf fix carried over
// from the bulk-snapshot design: a single `kube-bench run` calls RunChecks
// once per target (node, policies, CBP...). The object cache is shared across
// those calls, so an object fetched while resolving one target's failures is
// still cached for the next.
func TestObjectStoreCachedAcrossRunChecks(t *testing.T) {
	rs := ParentResource{Kind: "ReplicaSet", Namespace: "ns", Name: "web-rs", UID: "uid-rs"}
	orig := fetchOne
	resetObjectStoreCache()
	t.Cleanup(func() { fetchOne = orig; resetObjectStoreCache() })
	fn, calls := countingFetchOne(t)
	fetchOne = fn

	runner := stubRunner{resources: []FailedResource{{
		Kind: "Pod", Owners: []ParentResource{rs}, Parent: &rs, Scope: ScopeWorkload,
		Name: "p", UID: "u", Namespace: "ns",
	}}}
	runAll := func(*Group, *Check) bool { return true }

	// Simulate two targets from the same kube-bench run (e.g. node + cloudanix-1.0),
	// each with its own Controls/RunChecks call.
	policiesControls(t, 1).RunChecks(runner, runAll, map[string]bool{})
	policiesControls(t, 1).RunChecks(runner, runAll, map[string]bool{})

	for key, n := range calls {
		if n != 1 {
			t.Errorf("fetchOne calls for %s across two RunChecks = %d, want 1", key, n)
		}
	}
	if len(calls) == 0 {
		t.Fatal("fetchOne was never called")
	}
}
