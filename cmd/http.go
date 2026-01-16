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

type HttpPostConfig struct {
	AuthToken   string // Temporary storage for Auth Token
	ListenerUrl string `yaml:"listenerUrl"` // HTTP Listener URL
	NodeName    string `yaml:"nodeName"`    // Node Name

	AccountId         string `yaml:"accountId"`         // Unique Account Id
	ClusterIdentifier string `yaml:"clusterIdentifier"` // Cluster Identifier
	ClusterName       string `yaml:"clusterName"`       // Cluster Name
	ClusterDomain     string `yaml:"clusterDomain"`     // Cluster Domain
}

const (
	HeaderAuthorization     = "Authorization"
	HeaderAccountId         = "cdx-account-id"
	HeaderSessionId         = "cdx-session-id"
	HeaderClusterIdentifier = "cdx-cluster-identifier"
	HeaderClusterName       = "cdx-cluster-name"
	HeaderClusterDomain     = "cdx-cluster-domain"
	HeaderNode              = "cdx-node-name"
)

func marshalControls(controlsCollection []*check.Controls) ([]byte, error) {
	b, err := json.Marshal(controlsCollection)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func initHttpConfig(path string) (*HttpPostConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg *HttpPostConfig
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		return nil, err
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

	Rc := retry.NewClient().StandardClient()

	counter := 0

	for {
		req, err := http.NewRequest(http.MethodPost, cfg.ListenerUrl, bytes.NewReader(resultsJson))
		if err != nil {
			return nil
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Add(HeaderAuthorization, fmt.Sprintf("Bearer %s", cfg.AuthToken))

		req.Header.Add(HeaderSessionId, uuid.New().String())

		req.Header.Add(HeaderAccountId, cfg.AccountId)
		req.Header.Add(HeaderClusterIdentifier, cfg.ClusterIdentifier)
		req.Header.Add(HeaderClusterName, cfg.ClusterName)
		req.Header.Add(HeaderClusterDomain, cfg.ClusterDomain)
		req.Header.Add(HeaderNode, cfg.NodeName)

		counter++
		resp, err := Rc.Do(req)
		if err != nil {
			return err
		}

		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			// log.Fatalf("Error reading response %v", err)
			fmt.Printf("error reading response: %s %s\n", resp.Body, err)
		}

		fmt.Printf("response from post: %s\n", string(body))

		if err == nil && resp.StatusCode == http.StatusOK {
			return nil
		}

		if counter > 3 {
			return err
		}

		// sleep before next retry
		time.Sleep(4 * time.Second)
	}
}

func readSecretFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
