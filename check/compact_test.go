package check

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCompactResourcesSharesOneTableAcrossChecks(t *testing.T) {
	pod := FailedResource{
		Kind: "Pod", Scope: ScopeWorkload, Namespace: "default", Name: "web", UID: "u1",
		Labels: map[string]string{"app": "web"},
	}
	withAttrs := func(attrs map[string]string) FailedResource {
		fr := pod
		fr.Attributes = []map[string]string{attrs}
		return fr
	}
	c1 := &Check{ID: "C1.1", FailedResources: []FailedResource{withAttrs(map[string]string{"privileged": "true"})}}
	c2 := &Check{ID: "C1.2", FailedResources: []FailedResource{
		withAttrs(map[string]string{"runAsNonRoot": "false"}),
		{Kind: "Node", Scope: ScopeNode, Name: "ip-10-0-0-1"},
	}}
	c3 := &Check{ID: "1.1.1"} // no resources: must be left alone

	table := CompactResources([]*Controls{{Groups: []*Group{{Checks: []*Check{c1, c2, c3}}}}})

	if len(table) != 2 {
		t.Fatalf("table has %d entries, want 2 (one pod, one node): %+v", len(table), table)
	}
	key := pod.key()
	if got := table[key]; got.Labels["app"] != "web" || got.Attributes != nil {
		t.Errorf("table entry = %+v, want identity metadata and no attributes", got)
	}
	if c1.FailedResources != nil || c2.FailedResources != nil {
		t.Error("checks still carry expanded resources")
	}
	if len(c1.FailedResourceRefs) != 1 || c1.FailedResourceRefs[0].Ref != key ||
		c1.FailedResourceRefs[0].Attributes[0]["privileged"] != "true" {
		t.Errorf("c1 refs = %+v", c1.FailedResourceRefs)
	}
	if len(c2.FailedResourceRefs) != 2 || c2.FailedResourceRefs[0].Ref != key ||
		c2.FailedResourceRefs[0].Attributes[0]["runAsNonRoot"] != "false" {
		t.Errorf("c2 refs = %+v", c2.FailedResourceRefs)
	}
	if c3.FailedResourceRefs != nil {
		t.Errorf("check without resources grew refs: %+v", c3.FailedResourceRefs)
	}

	b, err := json.Marshal(c1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"failed_resources"`) || !strings.Contains(string(b), `"failed_resource_refs"`) {
		t.Errorf("compacted check marshals the wrong keys: %s", b)
	}
}
