// Copyright © 2026 Cloudanix Inc.
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

import "time"

// Nested inventory types. JSON tags match inventory-collector/objects.Resource
// so a failed_resource can create the same record the collector would, until
// inventory overwrites it.

type Container struct {
	Name      string `json:"name,omitempty"`
	Image     Image  `json:"image,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Operation string `json:"operation,omitempty"`
	Node      string `json:"node,omitempty"`

	ContainerID string `json:"containerID,omitempty"`

	RestartCount int32           `json:"restartCount,omitempty"`
	Ready        bool            `json:"ready,omitempty"`
	Started      *bool           `json:"started,omitempty"`
	State        *ContainerState `json:"state,omitempty"`

	SecurityContext *ContainerSecurityContext `json:"securityContext,omitempty"`
	Ports           []ContainerPort           `json:"ports,omitempty"`
	ConfigMapRefs   []string                  `json:"configMapRefs,omitempty"`
	SecretRefs      []string                  `json:"secretRefs,omitempty"`
	Resources       *ResourceRequests         `json:"resources,omitempty"`
}

type Condition struct {
	Type               string     `json:"type,omitempty"`
	Status             string     `json:"status,omitempty"`
	Reason             string     `json:"reason,omitempty"`
	LastTransitionTime *time.Time `json:"lastTransitionTime,omitempty"`
}

type ContainerState struct {
	Status   string `json:"status,omitempty"`
	Reason   string `json:"reason,omitempty"`
	ExitCode *int32 `json:"exitCode,omitempty"`
}

type PodSecurityContext struct {
	RunAsUser    *int64 `json:"runAsUser,omitempty"`
	RunAsNonRoot *bool  `json:"runAsNonRoot,omitempty"`
	FSGroup      *int64 `json:"fsGroup,omitempty"`
}

type ContainerSecurityContext struct {
	Privileged               *bool    `json:"privileged,omitempty"`
	RunAsUser                *int64   `json:"runAsUser,omitempty"`
	RunAsNonRoot             *bool    `json:"runAsNonRoot,omitempty"`
	ReadOnlyRootFilesystem   *bool    `json:"readOnlyRootFilesystem,omitempty"`
	AllowPrivilegeEscalation *bool    `json:"allowPrivilegeEscalation,omitempty"`
	CapabilitiesAdd          []string `json:"capabilitiesAdd,omitempty"`
	CapabilitiesDrop         []string `json:"capabilitiesDrop,omitempty"`
}

type HostPathVolume struct {
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
	Type string `json:"type,omitempty"`
}

type Toleration struct {
	Key      string `json:"key,omitempty"`
	Operator string `json:"operator,omitempty"`
	Value    string `json:"value,omitempty"`
	Effect   string `json:"effect,omitempty"`
}

type ResourceRequests struct {
	RequestsCPU    string `json:"requestsCpu,omitempty"`
	RequestsMemory string `json:"requestsMemory,omitempty"`
	LimitsCPU      string `json:"limitsCpu,omitempty"`
	LimitsMemory   string `json:"limitsMemory,omitempty"`
}

type ContainerPort struct {
	Name          string `json:"name,omitempty"`
	ContainerPort int32  `json:"containerPort,omitempty"`
	HostPort      int32  `json:"hostPort,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
}

type ServiceDetail struct {
	Type                string            `json:"type,omitempty"`
	ClusterIP           string            `json:"clusterIP,omitempty"`
	ExternalIPs         []string          `json:"externalIPs,omitempty"`
	LoadBalancerIngress []string          `json:"loadBalancerIngress,omitempty"`
	Ports               []ServicePort     `json:"ports,omitempty"`
	Selector            map[string]string `json:"selector,omitempty"`
	SessionAffinity     string            `json:"sessionAffinity,omitempty"`
}

type ServicePort struct {
	Name       string `json:"name,omitempty"`
	Port       int32  `json:"port,omitempty"`
	TargetPort string `json:"targetPort,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	NodePort   int32  `json:"nodePort,omitempty"`
}

type Image struct {
	Registry   string `json:"imageRegistry,omitempty"`
	Name       string `json:"imageName,omitempty"`
	Version    string `json:"imageVersion,omitempty"`
	Digest     string `json:"imageDigest,omitempty"`
	FullName   string `json:"imageFullName,omitempty"`
	Repository string `json:"imageRepository,omitempty"`
}

type NodeDetail struct {
	ProviderID   string            `json:"providerID,omitempty"`
	Addresses    []NodeAddress     `json:"addresses,omitempty"`
	Region       string            `json:"region,omitempty"`
	Zone         string            `json:"zone,omitempty"`
	InstanceType string            `json:"instanceType,omitempty"`
	Taints       []Taint           `json:"taints,omitempty"`
	Conditions   []Condition       `json:"conditions,omitempty"`
	Capacity     map[string]string `json:"capacity,omitempty"`
	Allocatable  map[string]string `json:"allocatable,omitempty"`
	Info         *NodeInfo         `json:"info,omitempty"`
}

type NodeAddress struct {
	Type    string `json:"type,omitempty"`
	Address string `json:"address,omitempty"`
}

type Taint struct {
	Key    string `json:"key,omitempty"`
	Value  string `json:"value,omitempty"`
	Effect string `json:"effect,omitempty"`
}

type NodeInfo struct {
	KernelVersion           string `json:"kernelVersion,omitempty"`
	OSImage                 string `json:"osImage,omitempty"`
	ContainerRuntimeVersion string `json:"containerRuntimeVersion,omitempty"`
	KubeletVersion          string `json:"kubeletVersion,omitempty"`
	Architecture            string `json:"architecture,omitempty"`
}

type EndpointSliceDetail struct {
	AddressType string     `json:"addressType,omitempty"`
	ServiceName string     `json:"serviceName,omitempty"`
	Endpoints   []Endpoint `json:"endpoints,omitempty"`
}

type Endpoint struct {
	Addresses  []string `json:"addresses,omitempty"`
	Ready      *bool    `json:"ready,omitempty"`
	NodeName   string   `json:"nodeName,omitempty"`
	TargetName string   `json:"targetName,omitempty"`
	TargetKind string   `json:"targetKind,omitempty"`
}
