package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func writeLimitFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "limit")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCgroupMemoryLimit(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	cases := []struct {
		name   string
		paths  []string
		want   int64
		wantOK bool
	}{
		{"v2 limit", []string{writeLimitFile(t, "536870912\n")}, 536870912, true},
		{"v2 unlimited", []string{writeLimitFile(t, "max\n")}, 0, false},
		{"v1 unlimited sentinel", []string{writeLimitFile(t, "9223372036854771712\n")}, 0, false},
		{"falls back to v1 when v2 missing", []string{missing, writeLimitFile(t, "1073741824")}, 1073741824, true},
		{"no cgroup files", []string{missing}, 0, false},
	}
	for _, c := range cases {
		got, ok := cgroupMemoryLimit(c.paths...)
		if got != c.want || ok != c.wantOK {
			t.Errorf("%s: got (%d, %v), want (%d, %v)", c.name, got, ok, c.want, c.wantOK)
		}
	}
}
