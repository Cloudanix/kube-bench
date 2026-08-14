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
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"gopkg.in/yaml.v2"
	"k8s.io/client-go/util/jsonpath"
)

// test:
// flag: OPTION
// set: (true|false)
// compare:
//   op: (eq|gt|gte|lt|lte|has)
//   value: val

type binOp string

const (
	and                   binOp = "and"
	or                          = "or"
	defaultArraySeparator       = ","
)

type tests struct {
	TestItems []*testItem `yaml:"test_items"`
	BinOp     binOp       `yaml:"bin_op"`
}

type AuditUsed string

const (
	AuditCommand AuditUsed = "auditCommand"
	AuditConfig  AuditUsed = "auditConfig"
	AuditEnv     AuditUsed = "auditEnv"
)

type testItem struct {
	Flag             string
	Env              string
	Path             string
	Output           string
	Value            string
	Set              bool
	Compare          compare
	isMultipleOutput bool
	auditUsed        AuditUsed
}

type (
	envTestItem  testItem
	pathTestItem testItem
	flagTestItem testItem
)

type compare struct {
	Op    string
	Value string
}

type testOutput struct {
	testResult      bool
	flagFound       bool
	actualResult    string
	ExpectedResult  string
	failedResources []FailedResource
}

// kvTokenRe matches the space-separated key=value tokens a CBP audit row is built from.
// Every value we emit (k8s names, UIDs, RFC3339 stamps, label pairs, image refs) is
// whitespace-free by k8s validation, so \S+ is an exact terminator.
var kvTokenRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)=(\S+)`)

// parseFailedResource turns one audit row into a FailedResource. Reserved keys map to
// struct fields; every other key lands in Attributes, which is the extension point — a
// new CBP check adds attributes without touching this function. Reports false when the
// row is not a Kubernetes object, which is what keeps file/process checks unaffected.
// See docs-internal/misconfig-cbp/failed-resources.md §4.
func parseFailedResource(row string) (FailedResource, bool) {
	// A kind= row is a Kubernetes object unless it says otherwise, which is what the
	// overwhelming majority of audits emit.
	fr := FailedResource{Scope: ScopeWorkload}
	// Cheap bail for file/process rows ("--anonymous-auth=false", "644"): with no kind=
	// token nothing here is a k8s object, so don't allocate the attribute map.
	if !strings.Contains(row, "kind=") {
		return FailedResource{}, false
	}
	// One row contributes at most one attribute set; resourceSet appends further sets when
	// other rows name the same object.
	attrs := map[string]string{}
	for _, m := range kvTokenRe.FindAllStringSubmatch(row, -1) {
		k, v := m[1], m[2]
		switch k {
		case "kind":
			fr.Kind = v
		case "ns":
			fr.Namespace = v
		case "name":
			fr.Name = v
		case "uid":
			fr.UID = v
		case "apiVersion":
			fr.APIVersion = v
		case "created":
			fr.CreationTimestamp = v
		case "node":
			fr.Node = v
		case "labels":
			fr.Labels = parseLabels(v)
		case "owner":
			if p, ok := parseParent(v); ok {
				fr.Owners = append(fr.Owners, p)
			}
		case "scope":
			// An audit declares a non-workload scope for findings that belong to the node
			// or the cluster rather than to an object in it. Unknown values are ignored so
			// a typo degrades to workload instead of reaching the backend as a new scope.
			if s := ResourceScope(v); validScopes[s] {
				fr.Scope = s
			}
		case "is_compliant":
			// the verdict the compare op reads, not metadata
		default:
			attrs[k] = v
		}
	}
	if len(attrs) > 0 {
		fr.Attributes = []map[string]string{attrs}
	}
	fr.setParentFromOwners()
	// A workload or node row is useless without a name. A cluster row is not: which cluster
	// this is already travels on the POST, so the row only has to declare its scope.
	if fr.Scope == ScopeCluster {
		return fr, fr.Kind != ""
	}
	return fr, fr.Kind != "" && fr.Name != ""
}

// setParentFromOwners points Parent at the last Owners entry, matching inventory's
// "parent is the root of the chain". A single owner= token makes that the immediate
// controller; a later walk replaces both fields with the full chain.
func (fr *FailedResource) setParentFromOwners() {
	if n := len(fr.Owners); n > 0 {
		last := fr.Owners[n-1]
		fr.Parent = &last
	}
}

// parseLabels decodes k:v,k:v. ':' and ',' are invalid in k8s label keys and values, so
// the encoding is unambiguous; '/' in a key prefix is preserved by cutting on the first ':'.
func parseLabels(s string) map[string]string {
	m := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		if k, v, ok := strings.Cut(kv, ":"); ok && k != "" {
			m[k] = v
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// parseParent decodes Kind/ns/name[/uid]; ns is empty for cluster-scoped owners.
func parseParent(s string) (ParentResource, bool) {
	p := strings.SplitN(s, "/", 4)
	if len(p) < 3 || p[0] == "" || p[2] == "" {
		return ParentResource{}, false
	}
	pr := ParentResource{Kind: p[0], Namespace: p[1], Name: p[2]}
	if len(p) == 4 {
		pr.UID = p[3]
	}
	return pr, true
}

func failTestItem(s string) *testOutput {
	return &testOutput{testResult: false, actualResult: s}
}

func (t testItem) value() string {
	if t.auditUsed == AuditConfig {
		return t.Path
	}

	if t.auditUsed == AuditEnv {
		return t.Env
	}

	return t.Flag
}

func (t testItem) findValue(s string) (match bool, value string, err error) {
	if t.auditUsed == AuditEnv {
		et := envTestItem(t)
		return et.findValue(s)
	}

	if t.auditUsed == AuditConfig {
		pt := pathTestItem(t)
		return pt.findValue(s)
	}

	ft := flagTestItem(t)
	return ft.findValue(s)
}

func (t flagTestItem) findValue(s string) (match bool, value string, err error) {
	if s == "" || t.Flag == "" {
		return
	}
	match = strings.Contains(s, t.Flag)
	if match {
		// Expects flags in the form;
		// --flag=somevalue
		// flag: somevalue
		// --flag
		// somevalue
		// DOESN'T COVER - use pathTestItem implementation of findValue() for this
		// flag:
		//	 - wehbook
		pttn := `(` + t.Flag + `)(=|: *)*([^\s]*) *`
		flagRe := regexp.MustCompile(pttn)
		vals := flagRe.FindStringSubmatch(s)

		if len(vals) > 0 {
			if vals[3] != "" {
				value = vals[3]
			} else {
				// --bool-flag
				if strings.HasPrefix(t.Flag, "--") {
					value = "true"
				} else {
					value = vals[1]
				}
			}
		} else {
			err = fmt.Errorf("invalid flag in testItem definition: %s", s)
		}
	}
	glog.V(3).Infof("In flagTestItem.findValue %s", value)

	return match, value, err
}

func (t pathTestItem) findValue(s string) (match bool, value string, err error) {
	var jsonInterface interface{}

	err = unmarshal(s, &jsonInterface)
	if err != nil {
		return false, "", fmt.Errorf("failed to load YAML or JSON from input \"%s\": %v", s, err)
	}

	value, err = executeJSONPath(t.Path, &jsonInterface)
	if err != nil {
		return false, "", fmt.Errorf("unable to parse path expression \"%s\": %v", t.Path, err)
	}

	glog.V(3).Infof("In pathTestItem.findValue %s", value)
	match = value != ""
	return match, value, err
}

func (t envTestItem) findValue(s string) (match bool, value string, err error) {
	if s != "" && t.Env != "" {
		r, _ := regexp.Compile(fmt.Sprintf("%s=.*(?:$|\\n)", t.Env))
		out := r.FindString(s)
		out = strings.Replace(out, "\n", "", 1)
		out = strings.Replace(out, fmt.Sprintf("%s=", t.Env), "", 1)

		if len(out) > 0 {
			match = true
			value = out
		} else {
			match = false
			value = ""
		}
	}
	glog.V(3).Infof("In envTestItem.findValue %s", value)
	return match, value, nil
}

func (t testItem) execute(s string) *testOutput {
	result := &testOutput{}
	s = strings.TrimRight(s, " \n")

	// If the test has output that should be evaluated for each row
	var output []string
	if t.isMultipleOutput {
		output = strings.Split(s, "\n")
	} else {
		output = []string{s}
	}

	// Multi-output checks visit every row so the full failing set is collected, but the
	// result still comes from the FIRST failing row (all-pass still ends on the last row),
	// so pass/fail semantics are unchanged. Single-output keeps the original early break.
	var failedRes resourceSet
	failed := false
	for _, op := range output {
		row := t.evaluate(op)
		if !row.testResult {
			if !failed {
				result = row
				failed = true
			}
			if fr, ok := parseFailedResource(op); ok {
				failedRes.add(fr)
			}
			if !t.isMultipleOutput {
				break
			}
		} else if !failed {
			result = row
		}
	}

	result.actualResult = s
	result.failedResources = failedRes.list
	return result
}

func (t testItem) evaluate(s string) *testOutput {
	result := &testOutput{}

	match, value, err := t.findValue(s)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return failTestItem(err.Error())
	}

	if t.Set {
		if match && t.Compare.Op != "" {
			result.ExpectedResult, result.testResult = compareOp(t.Compare.Op, value, t.Compare.Value, t.value())
		} else {
			result.ExpectedResult = fmt.Sprintf("'%s' is present", t.value())
			result.testResult = match
		}
	} else {
		result.ExpectedResult = fmt.Sprintf("'%s' is not present", t.value())
		result.testResult = !match
	}

	result.flagFound = match
	isExist := "exists"
	if !result.flagFound {
		isExist = "does not exist"
	}
	switch t.auditUsed {
	case AuditCommand:
		glog.V(3).Infof("Flag '%s' %s", t.Flag, isExist)
	case AuditConfig:
		glog.V(3).Infof("Path '%s' %s", t.Path, isExist)
	case AuditEnv:
		glog.V(3).Infof("Env '%s' %s", t.Env, isExist)
	default:
		glog.V(3).Infof("Error with identify audit used %s", t.auditUsed)
	}

	return result
}

func compareOp(tCompareOp string, flagVal string, tCompareValue string, flagName string) (string, bool) {
	expectedResultPattern := ""
	testResult := false

	switch tCompareOp {
	case "eq":
		expectedResultPattern = "'%s' is equal to '%s'"
		value := strings.ToLower(flagVal)
		// Do case insensitive comparaison for booleans ...
		if value == "false" || value == "true" {
			testResult = value == tCompareValue
		} else {
			testResult = flagVal == tCompareValue
		}

	case "noteq":
		expectedResultPattern = "'%s' is not equal to '%s'"
		value := strings.ToLower(flagVal)
		// Do case insensitive comparaison for booleans ...
		if value == "false" || value == "true" {
			testResult = !(value == tCompareValue)
		} else {
			testResult = !(flagVal == tCompareValue)
		}

	case "gt", "gte", "lt", "lte":
		a, b, err := toNumeric(flagVal, tCompareValue)
		if err != nil {
			expectedResultPattern = "Invalid Number(s) used for comparison: '%s' '%s'"
			glog.V(1).Infof(fmt.Sprintf("Not numeric value - flag: %q - compareValue: %q %v\n", flagVal, tCompareValue, err))
			return fmt.Sprintf(expectedResultPattern, flagVal, tCompareValue), false
		}
		switch tCompareOp {
		case "gt":
			expectedResultPattern = "'%s' is greater than %s"
			testResult = a > b

		case "gte":
			expectedResultPattern = "'%s' is greater or equal to %s"
			testResult = a >= b

		case "lt":
			expectedResultPattern = "'%s' is lower than %s"
			testResult = a < b

		case "lte":
			expectedResultPattern = "'%s' is lower or equal to %s"
			testResult = a <= b
		}

	case "has":
		expectedResultPattern = "'%s' has '%s'"
		testResult = strings.Contains(flagVal, tCompareValue)

	case "nothave":
		expectedResultPattern = "'%s' does not have '%s'"
		testResult = !strings.Contains(flagVal, tCompareValue)

	case "regex":
		expectedResultPattern = "'%s' matched by regex expression '%s'"
		opRe := regexp.MustCompile(tCompareValue)
		testResult = opRe.MatchString(flagVal)

	case "valid_elements":
		expectedResultPattern = "'%s' contains valid elements from '%s'"
		s := splitAndRemoveLastSeparator(flagVal, defaultArraySeparator)
		target := splitAndRemoveLastSeparator(tCompareValue, defaultArraySeparator)
		testResult = allElementsValid(s, target)

	case "bitmask":
		expectedResultPattern = "%s has permissions " + flagVal + ", expected %s or more restrictive"
		requested, err := strconv.ParseInt(flagVal, 8, 64)
		if err != nil {
			glog.V(1).Infof(fmt.Sprintf("Not numeric value - flag: %q - compareValue: %q %v\n", flagVal, tCompareValue, err))
			return fmt.Sprintf("Not numeric value - flag: %s", flagVal), false
		}
		max, err := strconv.ParseInt(tCompareValue, 8, 64)
		if err != nil {
			glog.V(1).Infof(fmt.Sprintf("Not numeric value - flag: %q - compareValue: %q %v\n", flagVal, tCompareValue, err))
			return fmt.Sprintf("Not numeric value - flag: %s", tCompareValue), false
		}
		testResult = (max & requested) == requested
	}
	if expectedResultPattern == "" {
		return expectedResultPattern, testResult
	}

	return fmt.Sprintf(expectedResultPattern, flagName, tCompareValue), testResult
}

func unmarshal(s string, jsonInterface *interface{}) error {
	data := []byte(s)
	err := json.Unmarshal(data, jsonInterface)
	if err != nil {
		err := yaml.Unmarshal(data, jsonInterface)
		if err != nil {
			return err
		}
	}
	return nil
}

func executeJSONPath(path string, jsonInterface interface{}) (string, error) {
	j := jsonpath.New("jsonpath")
	j.AllowMissingKeys(true)
	err := j.Parse(path)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	err = j.Execute(buf, jsonInterface)
	if err != nil {
		return "", err
	}
	jsonpathResult := buf.String()
	return jsonpathResult, nil
}

func allElementsValid(s, t []string) bool {
	sourceEmpty := len(s) == 0
	targetEmpty := len(t) == 0

	if sourceEmpty && targetEmpty {
		return true
	}

	// XOR comparison -
	//     if either value is empty and the other is not empty,
	//     not all elements are valid
	if (sourceEmpty || targetEmpty) && !(sourceEmpty && targetEmpty) {
		return false
	}

	for _, sv := range s {
		found := false
		for _, tv := range t {
			if sv == tv {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func splitAndRemoveLastSeparator(s, sep string) []string {
	cleanS := strings.TrimRight(strings.TrimSpace(s), sep)
	if len(cleanS) == 0 {
		return []string{}
	}

	ts := strings.Split(cleanS, sep)
	for i := range ts {
		ts[i] = strings.TrimSpace(ts[i])
	}

	return ts
}

func toNumeric(a, b string) (c, d int, err error) {
	c, err = strconv.Atoi(strings.TrimSpace(a))
	if err != nil {
		return -1, -1, fmt.Errorf("toNumeric - error converting %s: %s", a, err)
	}
	d, err = strconv.Atoi(strings.TrimSpace(b))
	if err != nil {
		return -1, -1, fmt.Errorf("toNumeric - error converting %s: %s", b, err)
	}

	return c, d, nil
}

func (t *testItem) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type buildTest testItem

	// Make Set parameter to be true by default.
	newTestItem := buildTest{Set: true}
	err := unmarshal(&newTestItem)
	if err != nil {
		return err
	}
	*t = testItem(newTestItem)
	return nil
}
