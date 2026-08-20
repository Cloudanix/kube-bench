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
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// objectFetchTimeout bounds each single-object kubectl get. Without it, an
// unresponsive API server hangs RunChecks (and the whole kube-bench run)
// forever on any one lookup in the owner walk.
const objectFetchTimeout = 30 * time.Second

// ownerChainLimit matches inventory-collector's walk bound against cyclic refs.
const ownerChainLimit = 16

func ownerKey(p ParentResource) string {
	return p.Kind + "/" + p.Namespace + "/" + p.Name
}

// kindToResource maps a Kind (as seen on a FailedResource or an
// ownerReference) to the lowercase resource name kubectl expects. Only kinds
// failed_resources / owner chains can actually name are listed; an unlisted
// Kind is a deliberate no-op in fetch, not an error.
var kindToResource = map[string]string{
	"Pod":                "pods",
	"ReplicaSet":         "replicasets",
	"Deployment":         "deployments",
	"DaemonSet":          "daemonsets",
	"StatefulSet":        "statefulsets",
	"Job":                "jobs",
	"CronJob":            "cronjobs",
	"Namespace":          "namespaces",
	"Node":               "nodes",
	"Role":               "roles",
	"RoleBinding":        "rolebindings",
	"ClusterRole":        "clusterroles",
	"ClusterRoleBinding": "clusterrolebindings",
	"ServiceAccount":     "serviceaccounts",
	"NetworkPolicy":      "networkpolicies",
	"Service":            "services",
}

// clusterScopedKinds never take a -n flag.
var clusterScopedKinds = map[string]bool{
	"Namespace":          true,
	"Node":               true,
	"ClusterRole":        true,
	"ClusterRoleBinding": true,
}

// objectStore is a per-process cache of individually-fetched kubectl objects.
// Unlike a bulk cluster snapshot, it only ever holds objects that were
// actually asked for: a failed resource plus however far up its owner chain
// gets walked. Every distinct object is fetched at most once per process, so
// many failed resources sharing one parent (e.g. pods under a Deployment)
// still pay for that parent only once, and the payload of each fetch is a
// single object instead of every object of every kind cluster-wide.
type objectStore struct {
	mu             sync.Mutex
	objs           map[string]*unstructured.Unstructured
	misses         map[string]bool
	clusterName    string
	clusterUID     string
	clusterUIDOnce sync.Once
}

func newObjectStore() *objectStore {
	return &objectStore{
		objs:        map[string]*unstructured.Unstructured{},
		misses:      map[string]bool{},
		clusterName: inventoryClusterName(),
	}
}

// fetchOne does a single-object kubectl get. Tests replace it.
var fetchOne = kubectlGetOne

func kubectlGetOne(resource, ns, name string, clusterScoped bool) ([]byte, error) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), objectFetchTimeout)
	defer cancel()
	args := []string{"get", resource, name, "-o", "json"}
	if !clusterScoped {
		args = append(args, "-n", ns)
	}
	return exec.CommandContext(ctx, "kubectl", args...).Output()
}

// get returns the object identified by kind/ns/name, fetching and caching it
// on first request. A Kind kube-bench has no mapping for, or a lookup that
// errors (RBAC, not found, kubectl missing, timeout), is cached as a
// permanent miss so a repeated request for the same object doesn't re-exec
// kubectl.
func (s *objectStore) get(kind, ns, name string) *unstructured.Unstructured {
	if s == nil || kind == "" || name == "" {
		return nil
	}
	key := ownerKey(ParentResource{Kind: kind, Namespace: ns, Name: name})

	s.mu.Lock()
	if o, ok := s.objs[key]; ok {
		s.mu.Unlock()
		return o
	}
	if s.misses[key] {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	o := s.fetch(kind, ns, name)

	s.mu.Lock()
	defer s.mu.Unlock()
	if o == nil {
		s.misses[key] = true
		return nil
	}
	s.objs[key] = o
	return o
}

func (s *objectStore) fetch(kind, ns, name string) *unstructured.Unstructured {
	resource, ok := kindToResource[kind]
	if !ok {
		return nil
	}
	data, err := fetchOne(resource, ns, name, clusterScopedKinds[kind])
	if err != nil {
		glog.V(2).Infof("inventory lookup skipped for %s %s/%s: %v", kind, ns, name, err)
		return nil
	}
	var o unstructured.Unstructured
	if err := json.Unmarshal(data, &o.Object); err != nil {
		glog.V(2).Infof("inventory lookup parse for %s %s/%s: %v", kind, ns, name, err)
		return nil
	}
	return &o
}

// getClusterUID resolves the cluster's UID from the kube-system Namespace,
// fetched (and cached) at most once per process, only when something actually
// needs it.
func (s *objectStore) getClusterUID() string {
	if s == nil {
		return ""
	}
	s.clusterUIDOnce.Do(func() {
		if ns := s.get("Namespace", "", "kube-system"); ns != nil {
			s.clusterUID = string(ns.GetUID())
		}
	})
	return s.clusterUID
}

// walkOwnerChain starts at the immediate controller and repeatedly fetches
// the current link's own object to read its owner, up to ownerChainLimit.
// Each link only costs a kubectl call the first time any failed resource's
// chain passes through it; siblings sharing a parent reuse the cached fetch.
// The last element is inventory's parent.
func walkOwnerChain(store *objectStore, start ParentResource) []ParentResource {
	chain := []ParentResource{start}
	if store == nil || start.Kind == "" || start.Name == "" {
		return chain
	}
	seen := map[string]bool{ownerKey(start): true}
	cur := start
	for i := 0; i < ownerChainLimit; i++ {
		o := store.get(cur.Kind, cur.Namespace, cur.Name)
		if o == nil {
			break
		}
		refs := o.GetOwnerReferences()
		if len(refs) == 0 {
			break
		}
		ref := refs[0]
		if ref.Kind == "" || ref.Name == "" {
			break
		}
		next := ParentResource{
			Kind: ref.Kind, Namespace: o.GetNamespace(), Name: ref.Name,
			UID: string(ref.UID), APIVersion: ref.APIVersion,
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

// resolveOwners walks fr's chain further via store when possible, then
// points Parent at the root. A nil store, or one that can't extend the
// chain, leaves a parsed chain alone so repeated owner= tokens still win.
func (fr *FailedResource) resolveOwners(store *objectStore) {
	if len(fr.Owners) == 0 {
		return
	}
	chain := walkOwnerChain(store, fr.Owners[0])
	if len(chain) > len(fr.Owners) {
		fr.Owners = chain
	}
	fr.setParentFromOwners()
}

func (c *Check) resolveFailedResourceOwners(store *objectStore) {
	for i := range c.FailedResources {
		c.FailedResources[i].resolveOwners(store)
	}
}

var (
	objectStoreOnce   sync.Once
	cachedObjectStore *objectStore
)

// getObjectStore returns the process-wide object cache, created at most once
// no matter how many RunChecks calls need it. A single `kube-bench run`
// invokes RunChecks once per target (node, policies, CBP...); sharing the
// store means an owner discovered while resolving one target's failures is
// still cached for the next.
func getObjectStore() *objectStore {
	objectStoreOnce.Do(func() {
		cachedObjectStore = newObjectStore()
	})
	return cachedObjectStore
}

// resetObjectStoreCache clears the memoized store so the next getObjectStore
// call builds a fresh one. Tests use this to get per-test isolation.
func resetObjectStoreCache() {
	objectStoreOnce = sync.Once{}
	cachedObjectStore = nil
}

func inventoryClusterName() string {
	if n, err := getConfig("CLUSTER_NAME"); err == nil && n != "" {
		return n
	}
	return os.Getenv("CLUSTER_NAME")
}
