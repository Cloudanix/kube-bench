// Copyright © 2023 Cloudanix Inc. <support@cloudanix.com>
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

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aquasecurity/kube-bench/check"
	"gopkg.in/yaml.v2"

	"github.com/google/uuid"
	retry "github.com/hashicorp/go-retryablehttp"
)

// HttpPostConfig is the effective config after merging the shared `common`
// block with the `misconfigCron` block (falling back to the legacy flat layout
// for in-place upgrades). The rest of the file reads these resolved fields.
type HttpPostConfig struct {
	AuthToken      string // Temporary storage for Auth Token
	NodeName       string // Node Name (from env)
	ServiceVersion string // Service Version (from env)

	ListenerUrl    string // shared (common): listener HTTP endpoint
	LogLevel       string // shared (common): debug / info / warn / error
	RequestTimeout int    // shared (common): listener HTTP request timeout, seconds
	HTTPMaxRetries int    // shared (common): max retries for the listener POST

	AccountId         string // Unique Account Id
	ClusterIdentifier string // Cluster Identifier
	ClusterName       string // Cluster Name
	ClusterDomain     string // Cluster Domain
}

// commonBlock is the shared `common` section read by every Cloudanix service.
// httpMaxRetries is a pointer so 0 (no retry) is distinguishable from absent.
type commonBlock struct {
	ListenerUrl    string `yaml:"listenerUrl"`
	LogLevel       string `yaml:"logLevel"`
	RequestTimeout int    `yaml:"requestTimeout"`
	HTTPMaxRetries *int   `yaml:"httpMaxRetries"`

	AccountId         string `yaml:"accountId"`
	ClusterIdentifier string `yaml:"clusterIdentifier"`
	ClusterName       string `yaml:"clusterName"`
	ClusterDomain     string `yaml:"clusterDomain"`
}

// serviceBlock is the `misconfigCron` section (service-level fields only).
type serviceBlock struct {
	Enabled      *bool  `yaml:"enabled"`
	TemplateType string `yaml:"templateType"`
}

// rawConfig mirrors the on-disk yaml: a `common` block plus this service's block.
type rawConfig struct {
	Common  commonBlock  `yaml:"common"`
	Service serviceBlock `yaml:"misconfigCron"`
}

// legacyConfig mirrors the pre-common flat config.yaml. Used as a fallback
// during in-place upgrades before config-cron rewrites the ConfigMap into the
// nested shape. AccountId lives only in common, so an empty resolved AccountId
// means the nested blocks were absent.
type legacyConfig struct {
	ListenerUrl       string `yaml:"listenerUrl"`
	AccountId         string `yaml:"accountId"`
	ClusterIdentifier string `yaml:"clusterIdentifier"`
	ClusterName       string `yaml:"clusterName"`
	ClusterDomain     string `yaml:"clusterDomain"`
}

const (
	HeaderAuthorization     = "Authorization"
	HeaderAccountId         = "cdx-account-id"
	HeaderSessionId         = "cdx-session-id"
	HeaderClusterIdentifier = "cdx-cluster-identifier"
	HeaderClusterName       = "cdx-cluster-name"
	HeaderClusterDomain     = "cdx-cluster-domain"
	HeaderNode              = "cdx-node-name"
	HeaderSvcVersion        = "cdx-service-version"
	HeaderTemplateType      = "cdx-template-type"
)

func marshalControls(controlsCollection []*check.Controls) ([]byte, error) {
	b, err := json.Marshal(controlsCollection)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func intDefault(v *int, def int) int {
	if v != nil {
		return *v
	}
	return def
}

func initHttpConfig(path string) (*HttpPostConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	cfg := &HttpPostConfig{
		ListenerUrl:       raw.Common.ListenerUrl,
		LogLevel:          raw.Common.LogLevel,
		RequestTimeout:    raw.Common.RequestTimeout,
		HTTPMaxRetries:    intDefault(raw.Common.HTTPMaxRetries, 3),
		AccountId:         raw.Common.AccountId,
		ClusterIdentifier: raw.Common.ClusterIdentifier,
		ClusterName:       raw.Common.ClusterName,
		ClusterDomain:     raw.Common.ClusterDomain,
	}

	// Legacy fallback: pre-common flat config.yaml. During an in-place upgrade
	// the new binary can start before config-cron rewrites the ConfigMap into the
	// nested shape; decode the flat layout so the service keeps working until then.
	if cfg.AccountId == "" {
		var legacy legacyConfig
		if err := yaml.Unmarshal(data, &legacy); err == nil {
			cfg.ListenerUrl = legacy.ListenerUrl
			cfg.AccountId = legacy.AccountId
			cfg.ClusterIdentifier = legacy.ClusterIdentifier
			cfg.ClusterName = legacy.ClusterName
			cfg.ClusterDomain = legacy.ClusterDomain
		}
	}

	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 30
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	return cfg, nil
}

// writeHttpOutput posts the results to the listener. Every failure exits
// non-zero: a scan whose results never reached the listener must surface as a
// Failed Job, not a Completed one, so CronJob status and diagnostics show it.
func writeHttpOutput(controlsCollection []*check.Controls) {
	resultsJson, err := marshalControls(controlsCollection)
	if err != nil {
		exitWithError(fmt.Errorf("failed to marshal controlsCollection: %w", err))
	}

	cfgFile := "/etc/cdx/config/config.yaml"
	cfg, err := initHttpConfig(cfgFile)
	if err != nil {
		exitWithError(fmt.Errorf("failed to load http-post config: %s - %w", cfgFile, err))
	}

	sctFile := "/etc/cdx/secrets/auth-token"
	cfg.AuthToken, err = readSecretFile(sctFile)
	if err != nil {
		// Keep going: the listener's 401 is then reported with full context below.
		fmt.Printf("Unable to initialize auth token: %v - %v\n", sctFile, err)
	}

	cfg.NodeName = os.Getenv("NODE_NAME")
	cfg.ServiceVersion = os.Getenv("SERVICE_VERSION")
	if cfg.ServiceVersion == "" {
		// No chart sets SERVICE_VERSION, and config-manager patches the image
		// without touching env, so the build-time version is the reliable one.
		cfg.ServiceVersion = KubeBenchVersion
	}

	fmt.Printf("scan summary: %s\n", summarizeControls(controlsCollection))

	if err := publishResults(cfg, resultsJson); err != nil {
		exitWithError(fmt.Errorf("failed to publish results to http endpoint: %w", err))
	}
}

// summarizeControls renders benchmark versions and pass/fail/warn totals so a
// customer's pod log shows what was scanned without the full payload.
func summarizeControls(controlsCollection []*check.Controls) string {
	var versions []string
	var pass, fail, warn int
	for _, c := range controlsCollection {
		versions = append(versions, c.Version)
		pass += c.Pass
		fail += c.Fail
		warn += c.Warn
	}
	return fmt.Sprintf("benchmarks=%s pass=%d fail=%d warn=%d", strings.Join(versions, ","), pass, fail, warn)
}

func publishResults(cfg *HttpPostConfig, resultsJson []byte) error {
	// retryablehttp retries on transport errors / 429 / 5xx with exponential
	// backoff up to RetryMax, reusing the same request body. Passthrough keeps
	// the final response after retries are exhausted so its status gets logged.
	rc := retry.NewClient()
	rc.RetryMax = cfg.HTTPMaxRetries
	rc.HTTPClient.Timeout = time.Duration(cfg.RequestTimeout) * time.Second
	rc.ErrorHandler = retry.PassthroughErrorHandler
	client := rc.StandardClient()

	req, err := http.NewRequest(http.MethodPost, cfg.ListenerUrl, bytes.NewReader(resultsJson))
	if err != nil {
		return err
	}

	sessionID := uuid.New().String()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add(HeaderAuthorization, fmt.Sprintf("Bearer %s", cfg.AuthToken))
	req.Header.Add(HeaderSessionId, sessionID)
	req.Header.Add(HeaderAccountId, cfg.AccountId)
	req.Header.Add(HeaderClusterIdentifier, cfg.ClusterIdentifier)
	req.Header.Add(HeaderClusterName, cfg.ClusterName)
	req.Header.Add(HeaderClusterDomain, cfg.ClusterDomain)
	req.Header.Add(HeaderNode, cfg.NodeName)
	req.Header.Add(HeaderSvcVersion, cfg.ServiceVersion)
	req.Header.Add(HeaderTemplateType, "KUBERNETESMISCONFIG")

	start := time.Now()
	resp, err := client.Do(req)
	status := "none"
	if resp != nil {
		status = resp.Status
	}
	// One greppable line per run: answers "did it send, where, what came back".
	// The session id matches the backend's cdx-session-id for cross-referencing.
	// Never the token value, only whether one is set.
	fmt.Printf("publish summary: url=%s status=%q bytes=%d duration=%s session=%s account=%s cluster=%s node=%s version=%q token_present=%t\n",
		redactURL(cfg.ListenerUrl), status, len(resultsJson), time.Since(start).Round(time.Millisecond),
		sessionID, cfg.AccountId, cfg.ClusterIdentifier, cfg.NodeName, cfg.ServiceVersion, strings.TrimSpace(cfg.AuthToken) != "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxLoggedResponseBytes))
	if err != nil {
		fmt.Printf("error reading response: %s\n", err)
	}

	fmt.Printf("response from post: %s\n", string(body))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, redactURL(cfg.ListenerUrl))
	}

	return nil
}

// maxLoggedResponseBytes caps how much of the listener's response body is logged.
const maxLoggedResponseBytes = 4096

// redactURL drops userinfo and query string, which could carry credentials.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<unparseable>"
	}
	u.User = nil
	u.RawQuery = ""
	return u.String()
}

func readSecretFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
