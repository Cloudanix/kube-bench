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
	"os"
	"os/exec"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ownerChainLimit matches inventory-collector's walk bound against cyclic refs.
const ownerChainLimit = 16

// ownerLookup maps Kind/ns/name of an object to its first ownerReference.
// Same walk inventory uses: ReplicaSet → Deployment, Job → CronJob.
type ownerLookup map[string]ParentResource

func ownerKey(p ParentResource) string {
	return p.Kind + "/" + p.Namespace + "/" + p.Name
}

// walkOwnerChain starts at the immediate controller and follows lookup up to
// the root. The last element is inventory's parent.
func walkOwnerChain(start ParentResource, lookup ownerLookup) []ParentResource {
	chain := []ParentResource{start}
	if lookup == nil || start.Kind == "" || start.Name == "" {
		return chain
	}
	seen := map[string]bool{ownerKey(start): true}
	cur := start
	for i := 0; i < ownerChainLimit; i++ {
		next, ok := lookup[ownerKey(cur)]
		if !ok || next.Kind == "" || next.Name == "" {
			break
		}
		k := ownerKey(next)
		if seen[k] {
			break
		}
		seen[k] = true
		chain = append(chain, next)
		cur = next
	}
	return chain
}

// resolveOwners replaces Owners with the walked chain when lookup can extend
// it, then points Parent at the root. A nil/empty lookup leaves a parsed chain
// alone so repeated owner= tokens still win.
func (fr *FailedResource) resolveOwners(lookup ownerLookup) {
	if len(fr.Owners) == 0 {
		return
	}
	chain := walkOwnerChain(fr.Owners[0], lookup)
	if len(chain) > len(fr.Owners) {
		fr.Owners = chain
	}
	fr.setParentFromOwners()
}

func (c *Check) resolveFailedResourceOwners(lookup ownerLookup) {
	for i := range c.FailedResources {
		c.FailedResources[i].resolveOwners(lookup)
	}
}

// k8sList is the kubectl -o json List shape used to build an objectStore
// without putting the dump on jq's argv (E2BIG).
type k8sList struct {
	Items []map[string]interface{} `json:"items"`
}

// objectStore is one kubectl snapshot: every object plus an owner lookup built
// from their ownerReferences. Failed resources are filled from here so the
// backend can create a provisional inventory row before the collector runs.
type objectStore struct {
	lookup      ownerLookup
	objs        map[string]*unstructured.Unstructured
	clusterName string
	clusterUID  string
}

func (s *objectStore) get(kind, ns, name string) *unstructured.Unstructured {
	if s == nil || s.objs == nil {
		return nil
	}
	return s.objs[ownerKey(ParentResource{Kind: kind, Namespace: ns, Name: name})]
}

func objectStoreFromListJSON(data []byte) (*objectStore, error) {
	var list k8sList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	store := &objectStore{
		lookup:      ownerLookup{},
		objs:        map[string]*unstructured.Unstructured{},
		clusterName: inventoryClusterName(),
	}
	for _, raw := range list.Items {
		o := &unstructured.Unstructured{Object: raw}
		kind, ns, name := o.GetKind(), o.GetNamespace(), o.GetName()
		if kind == "" || name == "" {
			continue
		}
		key := ownerKey(ParentResource{Kind: kind, Namespace: ns, Name: name})
		store.objs[key] = o
		if kind == "Namespace" && name == "kube-system" {
			store.clusterUID = string(o.GetUID())
		}
		refs := o.GetOwnerReferences()
		if len(refs) == 0 {
			continue
		}
		ref := refs[0]
		if ref.Kind == "" || ref.Name == "" {
			continue
		}
		store.lookup[key] = ParentResource{
			Kind: ref.Kind, Namespace: ns, Name: ref.Name,
			UID: string(ref.UID), APIVersion: ref.APIVersion,
		}
	}
	return store, nil
}

func ownerLookupFromListJSON(data []byte) (ownerLookup, error) {
	store, err := objectStoreFromListJSON(data)
	if err != nil {
		return nil, err
	}
	return store.lookup, nil
}

// inventorySnapshotResources is the one kubectl get that feeds both the owner
// walk and the inventory-shaped filler. Includes controllers plus every kind
// CBP failed_resources can name.
const inventorySnapshotResources = "pods,replicasets,deployments,daemonsets,statefulsets,jobs,cronjobs,namespaces,nodes,roles,rolebindings,clusterroles,clusterrolebindings,serviceaccounts,networkpolicies,services"

// fetchObjectStore loads the snapshot once per RunChecks. Tests replace it.
var fetchObjectStore = loadObjectStore

func loadObjectStore() *objectStore {
	if _, err := exec.LookPath("kubectl"); err != nil {
		return nil
	}
	cmd := exec.Command("kubectl", "get", inventorySnapshotResources, "--all-namespaces", "-o", "json")
	out, err := cmd.Output()
	if err != nil {
		glog.V(2).Infof("inventory snapshot skipped: %v", err)
		return nil
	}
	store, err := objectStoreFromListJSON(out)
	if err != nil {
		glog.V(2).Infof("inventory snapshot parse: %v", err)
		return nil
	}
	return store
}

func inventoryClusterName() string {
	if n, err := getConfig("CLUSTER_NAME"); err == nil && n != "" {
		return n
	}
	return os.Getenv("CLUSTER_NAME")
}
