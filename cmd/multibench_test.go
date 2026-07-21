package cmd

import (
	"reflect"
	"testing"
)

func TestGetBenchmarkVersions(t *testing.T) {
	viperWithData, err := loadConfigForTest()
	if err != nil {
		t.Fatalf("Unable to load config file %v", err)
	}

	cases := []struct {
		name             string
		kubeVersion      string
		benchmarkVersion string
		exp              []string
		succeed          bool
	}{
		{
			name:             "single explicit benchmark",
			benchmarkVersion: "cis-1.6",
			exp:              []string{"cis-1.6"},
			succeed:          true,
		},
		{
			name:             "comma-separated multi benchmark",
			benchmarkVersion: "eks-1.1.0,cloudanix-1.0",
			exp:              []string{"eks-1.1.0", "cloudanix-1.0"},
			succeed:          true,
		},
		{
			name:             "trims spaces and dedupes",
			benchmarkVersion: "cis-1.6, cis-1.6 ,eks-1.1.0",
			exp:              []string{"cis-1.6", "eks-1.1.0"},
			succeed:          true,
		},
		{
			name:             "skips empty segments",
			benchmarkVersion: "cis-1.6,,eks-1.1.0",
			exp:              []string{"cis-1.6", "eks-1.1.0"},
			succeed:          true,
		},
		{
			name:             "only separators is an error",
			benchmarkVersion: " , , ",
			succeed:          false,
		},
		{
			name:             "version + comma benchmark is an error",
			kubeVersion:      "1.24",
			benchmarkVersion: "cis-1.6,eks-1.1.0",
			succeed:          false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := getBenchmarkVersions(c.kubeVersion, c.benchmarkVersion, Platform{}, viperWithData)
			if c.succeed {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !reflect.DeepEqual(got, c.exp) {
					t.Fatalf("expected %v, got %v", c.exp, got)
				}
			} else if err == nil {
				t.Fatalf("expected error, got %v", got)
			}
		})
	}
}
