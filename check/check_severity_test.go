package check

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

// Severity is a CBP (Cloudanix Best Practices) addition. It carries no run
// logic; these tests lock the yaml/json wire tags the backend and console rely on.
func TestCheckSeverityYAMLUnmarshal(t *testing.T) {
	in := []byte("id: C1.1\nseverity: critical\n")
	var c Check
	if err := yaml.Unmarshal(in, &c); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if c.Severity != "critical" {
		t.Errorf("expected severity %q, got %q", "critical", c.Severity)
	}
}

func TestCheckSeverityJSONOmitEmpty(t *testing.T) {
	// Empty severity (every CIS check) must be omitted from JSON output.
	b, err := json.Marshal(Check{ID: "1.1.1"})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(b), "severity") {
		t.Errorf("empty severity should be omitted, got: %s", b)
	}

	b, err = json.Marshal(Check{ID: "C1.1", Severity: "high"})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if !strings.Contains(string(b), `"severity":"high"`) {
		t.Errorf("severity should be present, got: %s", b)
	}
}
