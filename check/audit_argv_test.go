package check

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Passing a captured kubectl dump to jq via --argjson puts the whole document on
// argv, so on a real cluster execve fails with E2BIG and the shell reports
// "jq: Argument list too long" (exit 126). kube-bench surfaces that as a FAIL with
// no failed_resources, which reads as a finding but is a broken audit.
// Stream both documents into jq -s instead.
var argvDumpPattern = regexp.MustCompile(`(?m)^\s*(\w+)=\$\(kubectl\b`)

func TestAuditsDoNotPassKubectlDumpsOnArgv(t *testing.T) {
	err := filepath.WalkDir("../cfg", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".yaml" {
			return err
		}
		in, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		body := string(in)
		for _, m := range argvDumpPattern.FindAllStringSubmatch(body, -1) {
			if strings.Contains(body, `--argjson `+m[1]+` "$`+m[1]+`"`) {
				t.Errorf("%s: jq --argjson %s \"$%s\" puts a kubectl dump on argv (E2BIG); "+
					"stream both documents into `jq -s` instead", path, m[1], m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk cfg: %v", err)
	}
}
