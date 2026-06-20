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
	"os"
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

func writeHttpOutput(controlsCollection []*check.Controls) {
	// fmt.Printf("processing http output \n")

	resultsJson, err := marshalControls(controlsCollection)
	if err != nil {
		fmt.Printf("failed to marshal controlsCollection: %s\n", err)
		return
	}

	cfgFile := "/etc/cdx/config/config.yaml"
	cfg, err := initHttpConfig(cfgFile)
	if err != nil {
		fmt.Printf("failed to load http-post config: %s - %s\n", cfgFile, err)
		return
	}

	sctFile := "/etc/cdx/secrets/auth-token"
	cfg.AuthToken, err = readSecretFile(sctFile)
	if err != nil {
		fmt.Printf("Unable to initialize auth token: %v - %v\n", sctFile, err)
	}

	fmt.Println("secrets initialized")

	cfg.NodeName = os.Getenv("NODE_NAME")
	cfg.ServiceVersion = os.Getenv("SVC_VERSION")

	// fmt.Printf("config: %s\n", cfg)

	err = publishResults(cfg, resultsJson)
	if err != nil {
		fmt.Printf("failed to publish results to http endpoint: %s \n", err)
		return
	}

	// viperConfigFile := "abc.json"
	// err = viper.WriteConfigAs(viperConfigFile)
	// if err != nil {
	// 	fmt.Printf("error writing viper config to file: %s \n", err)
	// }

	// dat, err := os.ReadFile(viperConfigFile)
	// if err != nil {
	// 	fmt.Printf("error reading viper config file: %s \n", err)
	// }
	// fmt.Printf("contents from abc.json config file: %s \n", string(dat))
}

func publishResults(cfg *HttpPostConfig, resultsJson []byte) error {
	// // fetch all env variables
	// for _, element := range os.Environ() {
	// 	variable := strings.Split(element, "=")
	// 	fmt.Println(variable[0], "=>", variable[1])
	// }

	// retryablehttp retries on transport errors / 429 / 5xx with exponential
	// backoff up to RetryMax, reusing the same request body.
	rc := retry.NewClient()
	rc.RetryMax = cfg.HTTPMaxRetries
	rc.HTTPClient.Timeout = time.Duration(cfg.RequestTimeout) * time.Second
	client := rc.StandardClient()

	req, err := http.NewRequest(http.MethodPost, cfg.ListenerUrl, bytes.NewReader(resultsJson))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Add(HeaderAuthorization, fmt.Sprintf("Bearer %s", cfg.AuthToken))

	req.Header.Add(HeaderSessionId, uuid.New().String())

	req.Header.Add(HeaderAccountId, cfg.AccountId)
	req.Header.Add(HeaderClusterIdentifier, cfg.ClusterIdentifier)
	req.Header.Add(HeaderClusterName, cfg.ClusterName)
	req.Header.Add(HeaderClusterDomain, cfg.ClusterDomain)
	req.Header.Add(HeaderNode, cfg.NodeName)
	req.Header.Add(HeaderSvcVersion, cfg.ServiceVersion)
	req.Header.Add(HeaderTemplateType, "KUBERNETESMISCONFIG")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("error reading response: %s\n", err)
	}

	fmt.Printf("response from post: %s\n", string(body))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, cfg.ListenerUrl)
	}

	return nil
}

func readSecretFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
