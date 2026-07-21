package check

import (
	"os"
	"testing"
)

// Validates the cloudanix-1.0 (CBP) benchmark files parse into Controls and hold
// the invariants the benchmark promises: automated checks are scored, severity'd,
// audited and multi-value; manual checks are typed manual.
func loadCBP(t *testing.T, path string, nodeType NodeType) *Controls {
	t.Helper()
	in, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	c, err := NewControls(nodeType, in, "cloudanix-1.0")
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return c
}

func allCBPChecks(c *Controls) []*Check {
	var checks []*Check
	for _, g := range c.Groups {
		checks = append(checks, g.Checks...)
	}
	return checks
}

func TestCloudanixPoliciesInvariants(t *testing.T) {
	c := loadCBP(t, "../cfg/cloudanix-1.0/policies.yaml", POLICIES)
	if c.Version != "cloudanix-1.0" {
		t.Errorf("version = %q, want cloudanix-1.0", c.Version)
	}

	validSeverity := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	checks := allCBPChecks(c)
	if len(checks) == 0 {
		t.Fatal("no checks parsed")
	}

	for _, chk := range checks {
		if len(chk.ID) == 0 || chk.ID[0] != 'C' {
			t.Errorf("check id %q should start with 'C'", chk.ID)
		}
		if !validSeverity[chk.Severity] {
			t.Errorf("%s: severity %q not in {critical,high,medium,low}", chk.ID, chk.Severity)
		}

		if chk.Type == MANUAL {
			if chk.Scored {
				t.Errorf("%s: manual check must not be scored", chk.ID)
			}
			continue
		}

		// Automated check invariants.
		if !chk.Scored {
			t.Errorf("%s: automated check should be scored", chk.ID)
		}
		if chk.Audit == "" {
			t.Errorf("%s: automated check needs an audit", chk.ID)
		}
		if chk.Tests == nil || len(chk.Tests.TestItems) == 0 {
			t.Errorf("%s: automated check needs tests", chk.ID)
		}
		if !chk.IsMultiple {
			t.Errorf("%s: automated check should set use_multiple_values", chk.ID)
		}
	}
}

func TestCloudanixManagedservicesParse(t *testing.T) {
	c := loadCBP(t, "../cfg/cloudanix-1.0/managedservices.yaml", MANAGEDSERVICES)
	checks := allCBPChecks(c)
	if len(checks) == 0 {
		t.Fatal("no checks parsed")
	}
	for _, chk := range checks {
		if chk.Type != MANUAL {
			t.Errorf("%s: advisory managedservices check should be manual", chk.ID)
		}
	}
}
