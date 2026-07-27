// Copyright © 2017 Aqua Security Software Ltd. <info@aquasec.com>
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
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/golang/glog"
)

// NodeType indicates the type of node (master, node).
type NodeType string

// State is the state of a control check.
type State string

const (
	// PASS check passed.
	PASS State = "PASS"
	// FAIL check failed.
	FAIL State = "FAIL"
	// WARN could not carry out check.
	WARN State = "WARN"
	// INFO informational message
	INFO State = "INFO"

	// SKIP for when a check should be skipped.
	SKIP = "skip"

	// MASTER a master node
	MASTER NodeType = "master"
	// NODE a node
	NODE NodeType = "node"
	// FEDERATED a federated deployment.
	FEDERATED NodeType = "federated"

	// ETCD an etcd node
	ETCD NodeType = "etcd"
	// CONTROLPLANE a control plane node
	CONTROLPLANE NodeType = "controlplane"
	// POLICIES a node to run policies from
	POLICIES NodeType = "policies"
	// MANAGEDSERVICES a node to run managedservices from
	MANAGEDSERVICES = "managedservices"

	// MANUAL Check Type
	MANUAL string = "manual"
)

// Check contains information about a recommendation in the
// CIS Kubernetes document.
type Check struct {
	ID             string   `yaml:"id" json:"test_number"`
	Text           string   `json:"test_desc"`
	Audit          string   `json:"audit"`
	AuditEnv       string   `yaml:"audit_env"`
	AuditConfig    string   `yaml:"audit_config"`
	Type           string   `json:"type"`
	Tests          *tests   `json:"-"`
	Set            bool     `json:"-"`
	Remediation    string   `json:"remediation"`
	TestInfo       []string `json:"test_info"`
	State          `json:"status"`
	ActualValue    string `json:"actual_value"`
	Scored         bool   `json:"scored"`
	IsMultiple     bool   `yaml:"use_multiple_values"`
	ExpectedResult string `json:"expected_result"`
	Reason         string `json:"reason,omitempty"`
	Severity       string `yaml:"severity" json:"severity,omitempty"`
	// References lists equivalent checks in other benchmarks as "family:id"
	// tokens (e.g. "eks:4.2.1"), used downstream to dedupe the same finding when
	// CBP is co-run with a platform benchmark. See docs-internal/misconfig-cbp.
	References []string `yaml:"references" json:"references,omitempty"`
	// FailedResources lists what failed this check: the Kubernetes objects parsed from the
	// kind=<Kind> tokens a kubectl audit emits, or — for the host-scoped targets, whose
	// audits name no object — the node itself. See addNodeResource and
	// docs-internal/misconfig-cbp/failed-resources.md.
	FailedResources   []FailedResource `json:"failed_resources,omitempty"`
	AuditOutput       string           `json:"-"`
	AuditEnvOutput    string           `json:"-"`
	AuditConfigOutput string           `json:"-"`
	DisableEnvTesting bool             `json:"-"`
	// usedAuditConfig records that the verdict came from AuditConfig rather than Audit, so
	// auditedFile names the config file the check actually read.
	usedAuditConfig bool
}

// ResourceScope says what kind of thing a FailedResource is, so downstream can resolve it
// against the right inventory instead of assuming everything is a Kubernetes object.
type ResourceScope string

const (
	// ScopeWorkload is an object in the cluster's API — Pod, Role, Namespace, Ingress.
	// Resolvable against the k8s inventory on (cluster_identifier, uid).
	ScopeWorkload ResourceScope = "workload"
	// ScopeNode is the machine a host-scoped check ran on. The cloud inventory knows it as
	// an EC2 / GCE / VMSS instance, not as a Kubernetes object, so it is linked by name.
	ScopeNode ResourceScope = "node"
	// ScopeCluster is the cluster as a whole, for findings that belong to no object in it.
	// Which cluster is already on the POST (cdx-cluster-identifier), so a row only has to
	// declare the scope. Audits opt in with a `scope=cluster` token.
	ScopeCluster ResourceScope = "cluster"
)

// validScopes gates what an audit row may declare, so a typo cannot invent a scope the
// backend has no branch for.
var validScopes = map[ResourceScope]bool{ScopeWorkload: true, ScopeNode: true, ScopeCluster: true}

// FailedResource identifies one thing that failed a check, with enough metadata for the
// console to render it standalone — i.e. without waiting for container-security-services'
// inventory-collector to report the same object. Field names mirror that service's
// objects.Resource so the backend can merge the two on (cluster_identifier, uid) with no
// mapping layer.
type FailedResource struct {
	Kind string `json:"kind"`
	// Scope distinguishes a Kubernetes object from the node or the cluster. Always set, so
	// downstream can branch on it without inferring from Kind.
	Scope             ResourceScope     `json:"scope"`
	Namespace         string            `json:"namespace,omitempty"`
	Name              string            `json:"name"`
	UID               string            `json:"uid,omitempty"`
	APIVersion        string            `json:"apiVersion,omitempty"`
	CreationTimestamp string            `json:"creationTimestamp,omitempty"`
	Node              string            `json:"node,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Owners            []ParentResource  `json:"owners,omitempty"`
	Attributes        map[string]string `json:"attributes,omitempty"`
}

// ParentResource is a controller ownerReference. Subset of inventory's ParentResource.
type ParentResource struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	UID       string `json:"uid,omitempty"`
}

// key identifies a FailedResource for dedup: identity plus its attribute set, so two
// failing containers in the same pod stay two entries.
func (f FailedResource) key() string {
	var b strings.Builder
	b.WriteString(string(f.Scope) + "/" + f.Kind + "/" + f.Namespace + "/" + f.Name + "/" + f.UID)
	ks := make([]string, 0, len(f.Attributes))
	for k := range f.Attributes {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		b.WriteString("|" + k + "=" + f.Attributes[k])
	}
	return b.String()
}

// Runner wraps the basic Run method.
type Runner interface {
	// Run runs a given check and returns the execution state.
	Run(c *Check) State
}

// NewRunner constructs a default Runner.
func NewRunner() Runner {
	return &defaultRunner{}
}

type defaultRunner struct{}

func (r *defaultRunner) Run(c *Check) State {
	return c.run()
}

// Run executes the audit commands specified in a check and outputs
// the results.
func (c *Check) run() State {
	glog.V(3).Infof("-----   Running check %v   -----", c.ID)
	// Since this is an Scored check
	// without tests return a 'WARN' to alert
	// the user that this check needs attention
	if c.Scored && strings.TrimSpace(c.Type) == "" && c.Tests == nil {
		c.Reason = "There are no tests"
		c.State = WARN
		glog.V(3).Info(c.Reason)
		return c.State
	}

	// If check type is skip, force result to INFO
	if c.Type == SKIP {
		c.Reason = "Test marked as skip"
		c.State = INFO
		glog.V(3).Info(c.Reason)
		return c.State
	}

	// If check type is manual force result to WARN
	if c.Type == MANUAL {
		c.Reason = "Test marked as a manual test"
		c.State = WARN
		glog.V(3).Info(c.Reason)
		return c.State
	}

	// If there aren't any tests defined this is a FAIL or WARN
	if c.Tests == nil || len(c.Tests.TestItems) == 0 {
		c.Reason = "No tests defined"
		if c.Scored {
			c.State = FAIL
		} else {
			c.State = WARN
		}
		glog.V(3).Info(c.Reason)
		return c.State
	}

	// Command line parameters override the setting in the config file, so if we get a good result from the Audit command that's all we need to run
	var finalOutput *testOutput
	var lastCommand string

	lastCommand, err := c.runAuditCommands()
	if err == nil {
		finalOutput, err = c.execute()
	}

	// An audit that never reached the API server (RBAC denial, no kubeconfig) emits no
	// rows, which the test_items read as a failing check — indistinguishable from a real
	// misconfiguration. Report it as WARN carrying the server's message instead.
	if msg := auditAccessError(c.AuditOutput); msg != "" {
		c.Reason = msg
		c.State = WARN
		c.ActualValue = c.AuditOutput
		glog.V(3).Info(c.Reason)
		return c.State
	}

	if finalOutput != nil {
		if finalOutput.testResult {
			c.State = PASS
		} else {
			if c.Scored {
				c.State = FAIL
			} else {
				c.State = WARN
			}
		}

		c.ActualValue = finalOutput.actualResult
		c.ExpectedResult = finalOutput.ExpectedResult
		c.FailedResources = finalOutput.failedResources
	}

	if err != nil {
		c.Reason = err.Error()
		if c.Scored {
			c.State = FAIL
		} else {
			c.State = WARN
		}
		glog.V(3).Info(c.Reason)
	}

	if finalOutput != nil {
		glog.V(3).Infof("Command: %q TestResult: %t State: %q \n", lastCommand, finalOutput.testResult, c.State)
	} else {
		glog.V(3).Infof("Command: %q TestResult: <<EMPTY>> \n", lastCommand)
	}

	if c.Reason != "" {
		glog.V(2).Info(c.Reason)
	}
	return c.State
}

// hostScopedTargets are the benchmark targets whose audits inspect the local machine
// (stat, ps, cat) rather than the API server. Their failing resource is the node itself.
var hostScopedTargets = map[NodeType]bool{MASTER: true, NODE: true, ETCD: true, CONTROLPLANE: true}

// addNodeResource gives host-scoped checks the same failed_resources shape the CBP kubectl
// checks get. Their audit prints bare values ("permissions=600", "root:root", a kubelet ps
// line) with no kind= token, so parseFailedResource skips them and the console is left with
// a finding it cannot attribute to anything. Here the node IS the resource, and the values
// the check actually tested become its attributes.
//
// No-op once a check has parsed real objects out of its output, so CBP — and any future
// audit that emits kind= rows — is untouched.
func (c *Check) addNodeResource(target NodeType, nodeName string) {
	if len(c.FailedResources) > 0 || nodeName == "" || !hostScopedTargets[target] {
		return
	}
	if c.State != FAIL && c.State != WARN {
		return
	}
	// Manual and skipped checks short-circuit in run() before their audit executes, and a
	// check with no test_items never runs one either; neither says anything about a node.
	// Every other check here did run, and its failure belongs to this machine even when the
	// audit printed nothing at all — `if test -e <file>` is silent when the file is absent,
	// and `ps -fC kubelet` is silent when the process is not running. Those are findings
	// about the node, so they get named rather than dropped for having no output.
	if c.Type == MANUAL || c.Type == SKIP || c.Tests == nil || len(c.Tests.TestItems) == 0 {
		return
	}

	fr := FailedResource{Kind: "Node", Scope: ScopeNode, Name: nodeName, Attributes: c.testedValues()}
	if audited := c.auditedFile(); audited != "" {
		if fr.Attributes == nil {
			fr.Attributes = map[string]string{}
		}
		fr.Attributes["file"] = audited
	}
	c.FailedResources = []FailedResource{fr}
}

// auditPathRe matches the whitespace-delimited absolute paths in an audit command. The
// leading boundary is load-bearing: without it `apiVersion=rbac.authorization.k8s.io/v1`
// and sed programs like `s/^/provider=/` yield bogus "paths".
var auditPathRe = regexp.MustCompile(`(?:^|\s)(/[^\s'";|]+)`)

// nonFilePrefixes are absolute paths that are not a file this check inspects:
//   - the audit's own tooling (/bin/sh, /bin/ps, /bin/cat)
//   - /dev/null and friends, which are redirect sinks — without this, `stat … 2>/dev/null`
//     reports /dev/null instead of the file it just stat'd
//   - apiserver URLs, which is what `kubectl get --raw /api/v1/nodes/…/configz` passes
var nonFilePrefixes = []string{
	"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/",
	"/dev/",
	"/api/", "/apis/",
}

// auditedFile names the file this check inspected, so a permissions or ownership finding
// says which file is wrong rather than only what the mode was. Variable substitution runs
// over the whole controls file before any check does (cmd/common.go), so $kubeletconf and
// friends are already real paths here and the subject is the last non-tooling path in the
// command. Empty when the audit inspects no file (`ps -fC kubelet`) — correctly so.
func (c *Check) auditedFile() string {
	cmd := c.Audit
	if c.usedAuditConfig {
		cmd = c.AuditConfig
	}

	var subject string
	for _, m := range auditPathRe.FindAllStringSubmatch(cmd, -1) {
		p := m[1]
		skip := false
		for _, d := range nonFilePrefixes {
			if strings.HasPrefix(p, d) {
				skip = true
				break
			}
		}
		if !skip {
			subject = p
		}
	}
	return subject
}

// hostTokenRe matches the key=value tokens host audits print, including the CLI forms
// ("--anonymous-auth=false") that kvTokenRe deliberately excludes because a k8s object row
// never contains them.
var hostTokenRe = regexp.MustCompile(`(?:^|\s)-{0,2}([A-Za-z_][A-Za-z0-9_.-]*)=(\S+)`)

// testedValues pulls out only the tokens this check's test_items name. A `ps -fC kubelet`
// line carries the node's entire flag set; recording all of it would bloat every result
// with data the check never looked at, so the observed value of each tested flag is what
// lands in Attributes. Returns nothing for path/env test_items — their audit output is a
// config file, not key=value rows.
func (c *Check) testedValues() map[string]string {
	if c.Tests == nil {
		return nil
	}
	wanted := map[string]bool{}
	for _, t := range c.Tests.TestItems {
		if f := strings.TrimLeft(t.Flag, "-"); f != "" {
			wanted[f] = true
		}
	}
	if len(wanted) == 0 {
		return nil
	}

	out := map[string]string{}
	for _, m := range hostTokenRe.FindAllStringSubmatch(c.ActualValue, -1) {
		if wanted[m[1]] {
			out[m[1]] = m[2]
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// auditAccessErrorPrefixes are what kubectl writes when it could not evaluate the audit at
// all — as opposed to evaluating it to a failing result. Matched on whole lines so an audit
// that legitimately prints one of these as data (none do today) needs it mid-line.
var auditAccessErrorPrefixes = []string{
	"Error from server",
	"error: You must be logged in to the server",
	"Unable to connect to the server",
	"The connection to the server",
}

// auditAccessError returns the first line of audit output showing the API server was never
// reached. Empty string when the output is a real audit result.
func auditAccessError(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		for _, p := range auditAccessErrorPrefixes {
			if strings.HasPrefix(line, p) {
				return line
			}
		}
	}
	return ""
}

func (c *Check) runAuditCommands() (lastCommand string, err error) {
	// Always run auditEnvOutput if needed
	if c.AuditEnv != "" {
		c.AuditEnvOutput, err = runAudit(c.AuditEnv)
		if err != nil {
			return c.AuditEnv, err
		}
	}

	// Run the audit command and auditConfig commands, if present
	c.AuditOutput, err = runAudit(c.Audit)
	if err != nil {
		return c.Audit, err
	}

	c.AuditConfigOutput, err = runAudit(c.AuditConfig)
	// when file not found then error comes as exit status 127
	// in some env same error comes as exit status 1
	if err != nil && (strings.Contains(err.Error(), "exit status 127") ||
		strings.Contains(err.Error(), "No such file or directory")) &&
		(c.AuditEnvOutput != "" || c.AuditOutput != "") {
		// suppress file not found error when there is Audit OR auditEnv output present
		glog.V(3).Info(err)
		err = nil
		c.AuditConfigOutput = ""
	}
	return c.AuditConfig, err
}

func (c *Check) execute() (finalOutput *testOutput, err error) {
	finalOutput = &testOutput{}

	ts := c.Tests
	res := make([]testOutput, len(ts.TestItems))
	expectedResultArr := make([]string, len(res))

	glog.V(3).Infof("Running %d test_items", len(ts.TestItems))
	for i, t := range ts.TestItems {

		t.isMultipleOutput = c.IsMultiple

		// Try with the auditOutput first, and if that's not found, try the auditConfigOutput
		t.auditUsed = AuditCommand
		result := *(t.execute(c.AuditOutput))

		// Check for AuditConfigOutput only if AuditConfig is set and auditConfigOutput is not empty
		if !result.flagFound && c.AuditConfig != "" && c.AuditConfigOutput != "" {
			// t.isConfigSetting = true
			t.auditUsed = AuditConfig
			result = *(t.execute(c.AuditConfigOutput))
			if !result.flagFound && t.Env != "" {
				t.auditUsed = AuditEnv
				result = *(t.execute(c.AuditEnvOutput))
			}
		}

		if !result.flagFound && t.Env != "" {
			t.auditUsed = AuditEnv
			result = *(t.execute(c.AuditEnvOutput))
		}
		glog.V(2).Infof("Used %s", t.auditUsed)
		if t.auditUsed == AuditConfig {
			c.usedAuditConfig = true
		}
		res[i] = result
		expectedResultArr[i] = res[i].ExpectedResult
	}

	var result bool
	// If no binary operation is specified, default to AND
	switch ts.BinOp {
	default:
		glog.V(2).Info(fmt.Sprintf("unknown binary operator for tests %s\n", ts.BinOp))
		finalOutput.actualResult = fmt.Sprintf("unknown binary operator for tests %s\n", ts.BinOp)
		return finalOutput, fmt.Errorf("unknown binary operator for tests %s", ts.BinOp)
	case and, "":
		result = true
		for i := range res {
			result = result && res[i].testResult
		}
		// Generate an AND expected result
		finalOutput.ExpectedResult = strings.Join(expectedResultArr, " AND ")

	case or:
		result = false
		for i := range res {
			result = result || res[i].testResult
		}
		// Generate an OR expected result
		finalOutput.ExpectedResult = strings.Join(expectedResultArr, " OR ")
	}

	finalOutput.testResult = result
	finalOutput.actualResult = res[0].actualResult

	// Union the per-test_item failed resources. The seen map is load-bearing even for a
	// single test_item: (*Check).execute may re-run an item against the auditConfig /
	// auditEnv output, and container-scoped checks emit one row per container.
	seen := map[string]bool{}
	for i := range res {
		for _, fr := range res[i].failedResources {
			if k := fr.key(); !seen[k] {
				seen[k] = true
				finalOutput.failedResources = append(finalOutput.failedResources, fr)
			}
		}
	}

	glog.V(3).Infof("Returning from execute on tests: finalOutput %#v", finalOutput)
	return finalOutput, nil
}

func runAudit(audit string) (output string, err error) {
	var out bytes.Buffer

	audit = strings.TrimSpace(audit)
	if len(audit) == 0 {
		return output, err
	}

	cmd := exec.Command("/bin/sh")
	cmd.Stdin = strings.NewReader(audit)
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	output = out.String()

	if err != nil {
		err = fmt.Errorf("failed to run: %q, output: %q, error: %s", audit, output, err)
	} else {
		glog.V(3).Infof("Command: %q", audit)
		glog.V(3).Infof("Output:\n %q", output)
	}
	return output, err
}
