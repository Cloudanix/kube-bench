package check

import "testing"

// A CBP audit denied by RBAC must not look like a real misconfiguration: WARN with the
// server's message, not FAIL. See docs-internal/misconfig-cbp/failed-resources.md.
func TestRunWarnsOnAuditAccessError(t *testing.T) {
	const forbidden = `Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:default:default" cannot list resource "pods" in API group "" at the cluster scope`

	c := &Check{
		ID:     "C1.1",
		Scored: true,
		Audit:  "echo '" + forbidden + "'\necho 'is_compliant=true'",
		Tests: &tests{TestItems: []*testItem{
			{Flag: "is_compliant", Set: true, Compare: compare{Op: "eq", Value: "true"}},
		}},
		IsMultiple: true,
	}

	if got := c.run(); got != WARN {
		t.Errorf("state = %v, want WARN", got)
	}
	if c.Reason != forbidden {
		t.Errorf("reason = %q, want the server message", c.Reason)
	}

	// A clean audit is untouched.
	ok := &Check{
		ID:     "C1.2",
		Scored: true,
		Audit:  "echo 'is_compliant=true'",
		Tests: &tests{TestItems: []*testItem{
			{Flag: "is_compliant", Set: true, Compare: compare{Op: "eq", Value: "true"}},
		}},
		IsMultiple: true,
	}
	if got := ok.run(); got != PASS {
		t.Errorf("clean audit state = %v (reason %q), want PASS", got, ok.Reason)
	}
}
