package cmd

import "testing"

func TestCloudanixBenchmarkRegistered(t *testing.T) {
	v, err := loadConfigForTest()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	vm, err := loadVersionMapping(v)
	if err != nil {
		t.Fatalf("version mapping: %v", err)
	}
	if vm["cloudanix-1.0"] != "cloudanix-1.0" {
		t.Errorf("cloudanix-1.0 missing from version_mapping, got %q", vm["cloudanix-1.0"])
	}

	cases := []struct {
		targets []string
		want    bool
	}{
		{[]string{"policies", "managedservices"}, true},
		{[]string{"master"}, false},
		{[]string{"node"}, false},
		{[]string{"etcd"}, false},
	}
	for _, c := range cases {
		got, err := validTargets("cloudanix-1.0", c.targets, v)
		if err != nil {
			t.Fatalf("validTargets(%v): %v", c.targets, err)
		}
		if got != c.want {
			t.Errorf("validTargets(cloudanix-1.0, %v) = %t, want %t", c.targets, got, c.want)
		}
	}
}
