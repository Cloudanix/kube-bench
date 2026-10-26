package check

import (
	"os/exec"
	"strings"
	"testing"
)

// C1.12 (liveness and readiness probes) is about long-running containers. Pods that
// run to completion (restartPolicy Never / OnFailure: every Job and CronJob pod) have
// nothing to probe, so they must not be reported. Runs the check's real jq program on
// a fixture pod list.
const probesFixture = `{"items": [
  {"metadata": {"namespace": "app", "name": "web-abc", "uid": "u1",
                "ownerReferences": [{"kind": "ReplicaSet", "name": "web-5d78c9869d", "uid": "r1", "controller": true}]},
   "spec": {"restartPolicy": "Always", "containers": [{"name": "web", "image": "web:1"}]}},
  {"metadata": {"namespace": "app", "name": "nightly-28901-xyz", "uid": "u2",
                "ownerReferences": [{"kind": "Job", "name": "nightly-28901", "uid": "j1", "controller": true}]},
   "spec": {"restartPolicy": "Never", "containers": [{"name": "job", "image": "job:1"}]}},
  {"metadata": {"namespace": "app", "name": "retry-xyz", "uid": "u3"},
   "spec": {"restartPolicy": "OnFailure", "containers": [{"name": "once", "image": "once:1"}]}},
  {"metadata": {"namespace": "app", "name": "bare", "uid": "u4"},
   "spec": {"containers": [{"name": "bare", "image": "bare:1"}]}}
]}`

func probesJQProgram(t *testing.T) string {
	t.Helper()
	c := loadCBP(t, "../cfg/cloudanix-1.0/policies.yaml", POLICIES)
	for _, chk := range allCBPChecks(c) {
		if chk.ID != "C1.12" {
			continue
		}
		start := strings.Index(chk.Audit, "jq -r '")
		end := strings.LastIndex(chk.Audit, "'")
		if start < 0 || end <= start {
			t.Fatalf("C1.12 audit has no jq -r '...' program: %q", chk.Audit)
		}
		return chk.Audit[start+len("jq -r '") : end]
	}
	t.Fatal("C1.12 not found")
	return ""
}

func runProbesJQ(t *testing.T, input string) string {
	t.Helper()
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("jq not installed")
	}
	cmd := exec.Command(jq, "-r", probesJQProgram(t))
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("jq: %v", err)
	}
	return string(out)
}

func TestProbesCheckSkipsRunToCompletionPods(t *testing.T) {
	out := runProbesJQ(t, probesFixture)

	for _, name := range []string{"name=web-abc ", "name=bare "} {
		if !strings.Contains(out, name) {
			t.Errorf("long-running pod %q missing from output:\n%s", name, out)
		}
	}
	for _, name := range []string{"name=nightly-28901-xyz ", "name=retry-xyz "} {
		if strings.Contains(out, name) {
			t.Errorf("run-to-completion pod %q reported:\n%s", name, out)
		}
	}
}

func TestProbesCheckPassesWhenOnlyJobPodsRun(t *testing.T) {
	jobsOnly := `{"items": [{"metadata": {"namespace": "app", "name": "j", "uid": "u"},
	  "spec": {"restartPolicy": "Never", "containers": [{"name": "c", "image": "i"}]}}]}`

	if out := strings.TrimSpace(runProbesJQ(t, jobsOnly)); out != "is_compliant=true" {
		t.Errorf("want the pass sentinel, got %q", out)
	}
}
