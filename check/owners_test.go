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
