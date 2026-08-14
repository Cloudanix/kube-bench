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
	"os/exec"

	"github.com/golang/glog"
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

// k8sList is the kubectl -o json List shape used to build an ownerLookup
// without putting the dump on jq's argv (E2BIG).
type k8sList struct {
	Items []k8sListItem `json:"items"`
}

type k8sListItem struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name            string              `json:"name"`
		Namespace       string              `json:"namespace"`
		OwnerReferences []k8sOwnerReference `json:"ownerReferences"`
	} `json:"metadata"`
}

type k8sOwnerReference struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	UID  string `json:"uid"`
}

func ownerLookupFromListJSON(data []byte) (ownerLookup, error) {
	var list k8sList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	lookup := ownerLookup{}
	for _, item := range list.Items {
		if item.Kind == "" || item.Metadata.Name == "" || len(item.Metadata.OwnerReferences) == 0 {
			continue
		}
		ref := item.Metadata.OwnerReferences[0]
		if ref.Kind == "" || ref.Name == "" {
			continue
		}
		lookup[ownerKey(ParentResource{
			Kind:      item.Kind,
			Namespace: item.Metadata.Namespace,
			Name:      item.Metadata.Name,
		})] = ParentResource{
			Kind:      ref.Kind,
			Namespace: item.Metadata.Namespace,
			Name:      ref.Name,
			UID:       ref.UID,
		}
	}
	return lookup, nil
}

// fetchOwnerLookup loads controller ownerReferences once per RunChecks.
// Tests replace it; production talks to kubectl. A failure returns nil so
// Parent stays the immediate controller the audit already named.
var fetchOwnerLookup = loadOwnerLookup

func loadOwnerLookup() ownerLookup {
	if _, err := exec.LookPath("kubectl"); err != nil {
		return nil
	}
	cmd := exec.Command("kubectl", "get",
		"replicasets,deployments,daemonsets,statefulsets,jobs,cronjobs",
		"--all-namespaces", "-o", "json")
	out, err := cmd.Output()
	if err != nil {
		glog.V(2).Infof("owner lookup skipped: %v", err)
		return nil
	}
	lookup, err := ownerLookupFromListJSON(out)
	if err != nil {
		glog.V(2).Infof("owner lookup parse: %v", err)
		return nil
	}
	return lookup
}

func failedResourceHasOwners(frs []FailedResource) bool {
	for i := range frs {
		if len(frs[i].Owners) > 0 {
			return true
		}
	}
	return false
}
