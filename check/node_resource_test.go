package check

import "testing"

func TestAddNodeResource(t *testing.T) {
	cases := []struct {
		name    string
		target  NodeType
		check   Check
		wantLen int
		attrs   map[string]string
	}{
		{
			name:   "file permission check names the file it stat'd",
			target: NODE,
			check: Check{
				State:       FAIL,
				ActualValue: "permissions=777",
				Audit:       `/bin/sh -c 'if test -e /var/lib/kubelet/kubeconfig; then stat -c permissions=%a /var/lib/kubelet/kubeconfig; fi' `,
				Tests: &tests{TestItems: []*testItem{
					{Flag: "permissions", Compare: compare{Op: "bitmask", Value: "644"}},
				}},
			},
			wantLen: 1,
			attrs: map[string]string{
				"permissions": "777",
				"file":        "/var/lib/kubelet/kubeconfig",
			},
		},
		{
			name:   "value read from audit_config names the config file",
			target: NODE,
			check: Check{
				State:           FAIL,
				ActualValue:     "authentication: {anonymous: {enabled: true}}",
				Audit:           "/bin/ps -fC /usr/bin/kubelet",
				AuditConfig:     "/bin/cat /etc/kubernetes/kubelet/kubelet-config.json",
				usedAuditConfig: true,
				Tests:           &tests{TestItems: []*testItem{{Path: "{.authentication.anonymous.enabled}"}}},
			},
			wantLen: 1,
			attrs:   map[string]string{"file": "/etc/kubernetes/kubelet/kubelet-config.json"},
		},
		{
			name:   "kubelet ps line keeps only the tested flag, and names no file",
			target: NODE,
			check: Check{
				State:       FAIL,
				Audit:       "/bin/ps -fC /usr/bin/kubelet",
				ActualValue: "root 1234 1 /usr/bin/kubelet --anonymous-auth=true --config=/etc/kubernetes/kubelet/kubelet-config.json",
				Tests: &tests{TestItems: []*testItem{
					{Flag: "--anonymous-auth", Compare: compare{Op: "eq", Value: "false"}},
				}},
			},
			wantLen: 1,
			attrs:   map[string]string{"anonymous-auth": "true"},
		},
		{
			name:   "redirect sink does not win over the stat'd file",
			target: MASTER,
			check: Check{
				State:       FAIL,
				ActualValue: "permissions=700",
				Audit:       `/bin/sh -c 'if test -e /etc/kubernetes/pki; then stat -c permissions=%a /etc/kubernetes/pki 2>/dev/null; fi'`,
				Tests: &tests{TestItems: []*testItem{
					{Flag: "permissions", Compare: compare{Op: "bitmask", Value: "755"}},
				}},
			},
			wantLen: 1,
			attrs:   map[string]string{"permissions": "700", "file": "/etc/kubernetes/pki"},
		},
		{
			name:   "api version token in an audit is not a file",
			target: MASTER,
			check: Check{
				State:       FAIL,
				ActualValue: "unsupportedConfigOverrides=set",
				Audit:       "oc get kubeapiserver/cluster -o jsonpath='{.spec.unsupportedConfigOverrides}' # rbac.authorization.k8s.io/v1",
				Tests:       &tests{TestItems: []*testItem{{Flag: "unsupportedConfigOverrides"}}},
			},
			wantLen: 1,
			attrs:   map[string]string{"unsupportedConfigOverrides": "set"},
		},
		{
			name:   "untokenized output still names the node",
			target: MASTER,
			check: Check{
				State:       FAIL,
				ActualValue: "nobody:nogroup",
				Tests:       &tests{TestItems: []*testItem{{Flag: "root:root"}}},
			},
			wantLen: 1,
		},
		{
			name:    "passing check gets nothing",
			target:  NODE,
			check:   Check{State: PASS, ActualValue: "permissions=644"},
			wantLen: 0,
		},
		{
			name:    "manual check gets nothing",
			target:  NODE,
			check:   Check{State: WARN, Reason: "Test marked as a manual test"},
			wantLen: 0,
		},
		{
			name:   "kubectl target is left to parseFailedResource",
			target: POLICIES,
			check: Check{
				State:       FAIL,
				ActualValue: "kind=Pod ns=default name=web is_compliant=false",
			},
			wantLen: 0,
		},
		{
			name:   "already-parsed resources are not overwritten",
			target: NODE,
			check: Check{
				State:           FAIL,
				ActualValue:     "permissions=777",
				FailedResources: []FailedResource{{Kind: "Pod", Name: "web"}},
			},
			wantLen: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.check
			c.addNodeResource(tc.target, "ip-10-0-1-23.ec2.internal")

			if len(c.FailedResources) != tc.wantLen {
				t.Fatalf("got %d resources, want %d: %+v", len(c.FailedResources), tc.wantLen, c.FailedResources)
			}
			if tc.wantLen == 0 || tc.attrs == nil {
				return
			}

			fr := c.FailedResources[0]
			if fr.Kind != "Node" || fr.Name != "ip-10-0-1-23.ec2.internal" {
				t.Errorf("identity = %s/%s, want Node/ip-10-0-1-23.ec2.internal", fr.Kind, fr.Name)
			}
			if len(fr.Attributes) != len(tc.attrs) {
				t.Fatalf("attributes = %v, want %v", fr.Attributes, tc.attrs)
			}
			for k, want := range tc.attrs {
				if got := fr.Attributes[k]; got != want {
					t.Errorf("attribute %s = %q, want %q", k, got, want)
				}
			}
		})
	}
}

// Without a node name there is nothing to identify the resource by, so emit none.
func TestAddNodeResourceNeedsNodeName(t *testing.T) {
	c := Check{State: FAIL, ActualValue: "permissions=777"}
	c.addNodeResource(NODE, "")
	if len(c.FailedResources) != 0 {
		t.Errorf("got %+v, want none", c.FailedResources)
	}
}
