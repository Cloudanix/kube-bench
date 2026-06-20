package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}

func TestInitHttpConfigCommonBlock(t *testing.T) {
	cfg, err := initHttpConfig(writeTempConfig(t, `
common:
  listenerUrl: https://events.cloudanix.com/cs
  logLevel: debug
  requestTimeout: 45
  httpMaxRetries: 5
  accountId: acc-1
  clusterIdentifier: arn:cluster
  clusterName: c1
  clusterDomain: AWS
misconfigCron:
  templateType: KUBERNETESMISCONFIG
`))
	if err != nil {
		t.Fatalf("initHttpConfig: %v", err)
	}
	if cfg.ListenerUrl != "https://events.cloudanix.com/cs" {
		t.Errorf("listenerUrl = %q", cfg.ListenerUrl)
	}
	if cfg.LogLevel != "debug" || cfg.RequestTimeout != 45 || cfg.HTTPMaxRetries != 5 {
		t.Errorf("common scalars = %q/%d/%d", cfg.LogLevel, cfg.RequestTimeout, cfg.HTTPMaxRetries)
	}
	if cfg.AccountId != "acc-1" || cfg.ClusterDomain != "AWS" {
		t.Errorf("account/cluster = %q/%q", cfg.AccountId, cfg.ClusterDomain)
	}
}

func TestInitHttpConfigDefaults(t *testing.T) {
	// common present (so no legacy fallback) but timeout/retries/logLevel absent.
	cfg, err := initHttpConfig(writeTempConfig(t, `
common:
  listenerUrl: https://events.cloudanix.com/cs
  accountId: acc-1
`))
	if err != nil {
		t.Fatalf("initHttpConfig: %v", err)
	}
	if cfg.RequestTimeout != 30 {
		t.Errorf("default requestTimeout = %d, want 30", cfg.RequestTimeout)
	}
	if cfg.HTTPMaxRetries != 3 {
		t.Errorf("default httpMaxRetries = %d, want 3", cfg.HTTPMaxRetries)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("default logLevel = %q, want info", cfg.LogLevel)
	}
}

func TestInitHttpConfigZeroRetriesDistinctFromAbsent(t *testing.T) {
	cfg, err := initHttpConfig(writeTempConfig(t, `
common:
  listenerUrl: https://events.cloudanix.com/cs
  accountId: acc-1
  httpMaxRetries: 0
`))
	if err != nil {
		t.Fatalf("initHttpConfig: %v", err)
	}
	if cfg.HTTPMaxRetries != 0 {
		t.Errorf("explicit httpMaxRetries 0 became %d", cfg.HTTPMaxRetries)
	}
}

func TestInitHttpConfigLegacyFlatFallback(t *testing.T) {
	// Old flat config (no common block) must still resolve during upgrades.
	cfg, err := initHttpConfig(writeTempConfig(t, `
listenerUrl: https://events.cloudanix.com/csmisconfigreceiver
accountId: legacy-acc
clusterIdentifier: arn:legacy
clusterName: lc
clusterDomain: AWS
`))
	if err != nil {
		t.Fatalf("initHttpConfig: %v", err)
	}
	if cfg.AccountId != "legacy-acc" || cfg.ListenerUrl != "https://events.cloudanix.com/csmisconfigreceiver" {
		t.Errorf("legacy fallback failed: %q / %q", cfg.AccountId, cfg.ListenerUrl)
	}
	if cfg.RequestTimeout != 30 || cfg.HTTPMaxRetries != 3 || cfg.LogLevel != "info" {
		t.Errorf("legacy defaults = %d/%d/%q", cfg.RequestTimeout, cfg.HTTPMaxRetries, cfg.LogLevel)
	}
}
