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

// ResourceRef is one entry of a compacted check's failed_resource_refs: a key into the
// payload-level resource table plus this check's own attribute sets. Attributes stay on
// the check because they are finding-scoped evidence (which container, which image);
// everything identity-shaped about the object lives once in the table.
type ResourceRef struct {
	Ref        string              `json:"ref"`
	Attributes []map[string]string `json:"attributes,omitempty"`
}

// CompactResources moves every check's FailedResources into one shared table and leaves
// each check holding only refs into it. The same Pod failing twenty checks used to be
// serialized twenty times, full inventory metadata included, which is what pushed a
// 70-node cluster's scan past the listener's 32 MiB request cap. Afterwards payload size
// grows with distinct objects, not objects × checks.
//
// First occurrence wins, which is also how the backend merges one object seen by several
// checks, except that gaps in it are filled from later occurrences (see fillGaps). The
// table is keyed by FailedResource.key, the identity the per-check dedup
// already uses. This rewrites the checks in place, so only the HTTP output calls it; the
// JSON file and ASFF outputs keep the expanded shape.
func CompactResources(controlsCollection []*Controls) map[string]FailedResource {
	resources := map[string]FailedResource{}
	for _, controls := range controlsCollection {
		for _, group := range controls.Groups {
			for _, c := range group.Checks {
				c.compactResources(resources)
			}
		}
	}
	return resources
}

func (c *Check) compactResources(resources map[string]FailedResource) {
	if len(c.FailedResources) == 0 {
		return
	}
	refs := make([]ResourceRef, 0, len(c.FailedResources))
	for _, fr := range c.FailedResources {
		k := fr.key()
		refs = append(refs, ResourceRef{Ref: k, Attributes: fr.Attributes})
		if prev, seen := resources[k]; seen {
			resources[k] = prev.fillGaps(fr)
			continue
		}
		fr.Attributes = nil // finding-scoped: travels on the ref, not the table
		resources[k] = fr
	}
	c.FailedResourceRefs = refs
	c.FailedResources = nil
}

// fillGaps copies into fr what only other's audit row knew. With an inventory store every
// copy of an object is enriched identically, but without one (no RBAC, kubectl failed) each
// check's copy holds just the tokens its own audit printed. Before compaction each check
// kept its own copy, so a check whose row carried owner= still attributed its finding to
// the Deployment; keeping only the first copy would silently re-parent it to the cluster.
func (fr FailedResource) fillGaps(other FailedResource) FailedResource {
	// A longer chain is the more resolved one; Parent is derived from it.
	if len(other.Owners) > len(fr.Owners) {
		fr.Owners, fr.Parent = other.Owners, other.Parent
	}
	if len(fr.Labels) == 0 {
		fr.Labels = other.Labels
	}
	if fr.APIVersion == "" {
		fr.APIVersion = other.APIVersion
	}
	if fr.CreationTimestamp == "" {
		fr.CreationTimestamp = other.CreationTimestamp
	}
	if fr.Node == "" {
		fr.Node = other.Node
	}
	return fr
}
