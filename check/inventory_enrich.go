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

import (
	"strings"
	"time"

	"github.com/distribution/reference"
	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// annotationWhitelist is the exact set inventory captures. last-applied-config
// is excluded — it is a full spec blob.
var annotationWhitelist = map[string]bool{
	"sidecar.istio.io/inject": true,
	"linkerd.io/inject":       true,
	"prometheus.io/scrape":    true,
	"prometheus.io/port":      true,
	"prometheus.io/path":      true,
}

func (c *Check) fillInventory(store *objectStore) {
	if store == nil {
		return
	}
	now := time.Now().Unix()
	for i := range c.FailedResources {
		c.FailedResources[i].fillInventory(store, now)
	}
}

func (fr *FailedResource) fillInventory(store *objectStore, eventTime int64) {
	o := store.get(fr.Kind, fr.Namespace, fr.Name)
	if o == nil {
		fr.resolveOwners(store.lookup)
		return
	}
	applyInventoryIdentity(fr, o, store.clusterName, store.clusterUID, eventTime)
	if refs := o.GetOwnerReferences(); len(refs) > 0 {
		start := ParentResource{
			Kind: refs[0].Kind, Namespace: o.GetNamespace(),
			Name: refs[0].Name, UID: string(refs[0].UID), APIVersion: refs[0].APIVersion,
		}
		fr.Owners = walkOwnerChain(start, store.lookup)
		fr.setParentFromOwners()
	} else {
		fr.resolveOwners(store.lookup)
	}
	switch fr.Kind {
	case "Pod":
		enrichPod(fr, o)
	case "Node":
		enrichNode(fr, o)
	case "Service":
		enrichService(fr, o)
	case "EndpointSlice":
		enrichEndpointSlice(fr, o)
	}
}

func applyInventoryIdentity(fr *FailedResource, o *unstructured.Unstructured, clusterName, clusterUID string, eventTime int64) {
	fr.Name = o.GetName()
	fr.Namespace = o.GetNamespace()
	fr.Kind = o.GetKind()
	fr.APIVersion = o.GetAPIVersion()
	fr.GenerateName = o.GetGenerateName()
	fr.UID = string(o.GetUID())
	fr.ResourceVersion = o.GetResourceVersion()
	fr.Generation = o.GetGeneration()
	fr.ObservedGeneration = observedGeneration(o)
	if ts := o.GetCreationTimestamp(); !ts.IsZero() {
		fr.CreationTimestamp = ts.UTC().Format(time.RFC3339)
	}
	if dt := o.GetDeletionTimestamp(); dt != nil {
		t := dt.Time
		fr.DeletionTimestamp = &t
	}
	fr.Labels = o.GetLabels()
	fr.Annotations = whitelistAnnotations(o.GetAnnotations())
	gvk := o.GroupVersionKind()
	fr.Group = gvk.Group
	fr.Version = gvk.Version
	fr.ClusterName = clusterName
	fr.ClusterUID = clusterUID
	fr.Event = "create"
	fr.EventTime = eventTime
}

func enrichPod(fr *FailedResource, o *unstructured.Unstructured) {
	var p v1.Pod
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(o.Object, &p); err != nil {
		return
	}
	fr.Node = p.Spec.NodeName
	fr.Hostname = p.Spec.Hostname
	fr.Subdomain = p.Spec.Subdomain
	fr.SchedulerName = p.Spec.SchedulerName
	if p.Spec.OS != nil {
		fr.OS = string(p.Spec.OS.Name)
	}
	fr.PodIP = p.Status.PodIP
	fr.HostIP = p.Status.HostIP
	for _, ip := range p.Status.PodIPs {
		fr.PodIPs = append(fr.PodIPs, ip.IP)
	}
	fr.Phase = string(p.Status.Phase)
	fr.QOSClass = string(p.Status.QOSClass)
	if p.Status.StartTime != nil {
		t := p.Status.StartTime.Time
		fr.StartTime = &t
	}
	fr.Conditions = podConditions(p.Status.Conditions)
	fr.HostPID = p.Spec.HostPID
	fr.HostIPC = p.Spec.HostIPC
	fr.HostNetwork = p.Spec.HostNetwork
	fr.ServiceAccountName = p.Spec.ServiceAccountName
	fr.AutomountServiceAccountToken = p.Spec.AutomountServiceAccountToken
	fr.SecurityContext = podSecurityContext(p.Spec.SecurityContext)
	fr.NodeSelector = p.Spec.NodeSelector
	fr.PriorityClassName = p.Spec.PriorityClassName
	fr.Tolerations = podTolerations(p.Spec.Tolerations)
	collectVolumeRefs(fr, p.Spec.Volumes)

	statusByName := map[string]v1.ContainerStatus{}
	for _, cs := range p.Status.ContainerStatuses {
		statusByName[cs.Name] = cs
	}
	containers := make([]Container, 0, len(p.Spec.Containers))
	for _, container := range p.Spec.Containers {
		cs, hasStatus := statusByName[container.Name]
		image := parseImage(container.Image)
		if hasStatus {
			if digest := extractDigest(cs.ImageID); digest != "" {
				image.Digest = digest
			}
		}
		oc := Container{
			Name:            container.Name,
			Namespace:       fr.Namespace,
			Operation:       fr.Event,
			Node:            fr.Node,
			Image:           image,
			SecurityContext: containerSecurityContext(container.SecurityContext),
			Ports:           containerPorts(container.Ports),
			Resources:       resourceRequests(container.Resources),
		}
		collectContainerEnvRefs(&oc, container)
		if hasStatus {
			oc.ContainerID = cs.ContainerID
			oc.RestartCount = cs.RestartCount
			oc.Ready = cs.Ready
			oc.Started = cs.Started
			oc.State = containerState(cs.State)
		}
		containers = append(containers, oc)
	}
	fr.Containers = containers
}

func observedGeneration(o *unstructured.Unstructured) int64 {
	v, found, err := unstructured.NestedInt64(o.Object, "status", "observedGeneration")
	if err != nil || !found {
		return 0
	}
	return v
}

func podConditions(conds []v1.PodCondition) []Condition {
	if len(conds) == 0 {
		return nil
	}
	out := make([]Condition, 0, len(conds))
	for _, c := range conds {
		oc := Condition{Type: string(c.Type), Status: string(c.Status), Reason: c.Reason}
		if !c.LastTransitionTime.IsZero() {
			t := c.LastTransitionTime.Time
			oc.LastTransitionTime = &t
		}
		out = append(out, oc)
	}
	return out
}

func podTolerations(tols []v1.Toleration) []Toleration {
	if len(tols) == 0 {
		return nil
	}
	out := make([]Toleration, 0, len(tols))
	for _, t := range tols {
		out = append(out, Toleration{
			Key: t.Key, Operator: string(t.Operator), Value: t.Value, Effect: string(t.Effect),
		})
	}
	return out
}

func collectVolumeRefs(fr *FailedResource, vols []v1.Volume) {
	for _, v := range vols {
		switch {
		case v.ConfigMap != nil:
			fr.ConfigMapRefs = append(fr.ConfigMapRefs, v.ConfigMap.Name)
		case v.Secret != nil:
			fr.SecretRefs = append(fr.SecretRefs, v.Secret.SecretName)
		case v.PersistentVolumeClaim != nil:
			fr.PVCRefs = append(fr.PVCRefs, v.PersistentVolumeClaim.ClaimName)
		case v.HostPath != nil:
			hp := HostPathVolume{Name: v.Name, Path: v.HostPath.Path}
			if v.HostPath.Type != nil {
				hp.Type = string(*v.HostPath.Type)
			}
			fr.HostPathVolumes = append(fr.HostPathVolumes, hp)
		}
	}
}

func collectContainerEnvRefs(oc *Container, c v1.Container) {
	for _, ef := range c.EnvFrom {
		if ef.ConfigMapRef != nil {
			oc.ConfigMapRefs = append(oc.ConfigMapRefs, ef.ConfigMapRef.Name)
		}
		if ef.SecretRef != nil {
			oc.SecretRefs = append(oc.SecretRefs, ef.SecretRef.Name)
		}
	}
	for _, e := range c.Env {
		if e.ValueFrom == nil {
			continue
		}
		if e.ValueFrom.ConfigMapKeyRef != nil {
			oc.ConfigMapRefs = append(oc.ConfigMapRefs, e.ValueFrom.ConfigMapKeyRef.Name)
		}
		if e.ValueFrom.SecretKeyRef != nil {
			oc.SecretRefs = append(oc.SecretRefs, e.ValueFrom.SecretKeyRef.Name)
		}
	}
}

func resourceRequests(r v1.ResourceRequirements) *ResourceRequests {
	out := &ResourceRequests{}
	if q, ok := r.Requests[v1.ResourceCPU]; ok {
		out.RequestsCPU = q.String()
	}
	if q, ok := r.Requests[v1.ResourceMemory]; ok {
		out.RequestsMemory = q.String()
	}
	if q, ok := r.Limits[v1.ResourceCPU]; ok {
		out.LimitsCPU = q.String()
	}
	if q, ok := r.Limits[v1.ResourceMemory]; ok {
		out.LimitsMemory = q.String()
	}
	if *out == (ResourceRequests{}) {
		return nil
	}
	return out
}

func podSecurityContext(sc *v1.PodSecurityContext) *PodSecurityContext {
	if sc == nil {
		return nil
	}
	if sc.RunAsUser == nil && sc.RunAsNonRoot == nil && sc.FSGroup == nil {
		return nil
	}
	return &PodSecurityContext{RunAsUser: sc.RunAsUser, RunAsNonRoot: sc.RunAsNonRoot, FSGroup: sc.FSGroup}
}

func containerSecurityContext(sc *v1.SecurityContext) *ContainerSecurityContext {
	if sc == nil {
		return nil
	}
	out := &ContainerSecurityContext{
		Privileged: sc.Privileged, RunAsUser: sc.RunAsUser, RunAsNonRoot: sc.RunAsNonRoot,
		ReadOnlyRootFilesystem: sc.ReadOnlyRootFilesystem, AllowPrivilegeEscalation: sc.AllowPrivilegeEscalation,
	}
	if sc.Capabilities != nil {
		for _, c := range sc.Capabilities.Add {
			out.CapabilitiesAdd = append(out.CapabilitiesAdd, string(c))
		}
		for _, c := range sc.Capabilities.Drop {
			out.CapabilitiesDrop = append(out.CapabilitiesDrop, string(c))
		}
	}
	return out
}

func containerState(s v1.ContainerState) *ContainerState {
	switch {
	case s.Running != nil:
		return &ContainerState{Status: "running"}
	case s.Waiting != nil:
		return &ContainerState{Status: "waiting", Reason: s.Waiting.Reason}
	case s.Terminated != nil:
		code := s.Terminated.ExitCode
		return &ContainerState{Status: "terminated", Reason: s.Terminated.Reason, ExitCode: &code}
	}
	return nil
}

func enrichNode(fr *FailedResource, o *unstructured.Unstructured) {
	var n v1.Node
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(o.Object, &n); err != nil {
		return
	}
	nd := &NodeDetail{
		ProviderID:   n.Spec.ProviderID,
		Region:       n.Labels["topology.kubernetes.io/region"],
		Zone:         n.Labels["topology.kubernetes.io/zone"],
		InstanceType: n.Labels["node.kubernetes.io/instance-type"],
	}
	for _, a := range n.Status.Addresses {
		nd.Addresses = append(nd.Addresses, NodeAddress{Type: string(a.Type), Address: a.Address})
	}
	for _, t := range n.Spec.Taints {
		nd.Taints = append(nd.Taints, Taint{Key: t.Key, Value: t.Value, Effect: string(t.Effect)})
	}
	for _, c := range n.Status.Conditions {
		switch c.Type {
		case v1.NodeReady, v1.NodeMemoryPressure, v1.NodeDiskPressure:
			oc := Condition{Type: string(c.Type), Status: string(c.Status), Reason: c.Reason}
			if !c.LastTransitionTime.IsZero() {
				tt := c.LastTransitionTime.Time
				oc.LastTransitionTime = &tt
			}
			nd.Conditions = append(nd.Conditions, oc)
		}
	}
	nd.Capacity = quantityMap(n.Status.Capacity)
	nd.Allocatable = quantityMap(n.Status.Allocatable)
	info := n.Status.NodeInfo
	nd.Info = &NodeInfo{
		KernelVersion: info.KernelVersion, OSImage: info.OSImage,
		ContainerRuntimeVersion: info.ContainerRuntimeVersion,
		KubeletVersion:          info.KubeletVersion, Architecture: info.Architecture,
	}
	fr.NodeDetail = nd
}

func quantityMap(rl v1.ResourceList) map[string]string {
	if len(rl) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range rl {
		out[string(k)] = v.String()
	}
	return out
}

func containerPorts(ports []v1.ContainerPort) []ContainerPort {
	if len(ports) == 0 {
		return nil
	}
	out := make([]ContainerPort, 0, len(ports))
	for _, p := range ports {
		out = append(out, ContainerPort{
			Name: p.Name, ContainerPort: p.ContainerPort, HostPort: p.HostPort, Protocol: string(p.Protocol),
		})
	}
	return out
}

func enrichService(fr *FailedResource, o *unstructured.Unstructured) {
	var s v1.Service
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(o.Object, &s); err != nil {
		return
	}
	sd := &ServiceDetail{
		Type: string(s.Spec.Type), ClusterIP: s.Spec.ClusterIP, ExternalIPs: s.Spec.ExternalIPs,
		Selector: s.Spec.Selector, SessionAffinity: string(s.Spec.SessionAffinity),
	}
	for _, ing := range s.Status.LoadBalancer.Ingress {
		if ing.IP != "" {
			sd.LoadBalancerIngress = append(sd.LoadBalancerIngress, ing.IP)
		} else if ing.Hostname != "" {
			sd.LoadBalancerIngress = append(sd.LoadBalancerIngress, ing.Hostname)
		}
	}
	for _, p := range s.Spec.Ports {
		sd.Ports = append(sd.Ports, ServicePort{
			Name: p.Name, Port: p.Port, TargetPort: p.TargetPort.String(),
			Protocol: string(p.Protocol), NodePort: p.NodePort,
		})
	}
	fr.Service = sd
}

func enrichEndpointSlice(fr *FailedResource, o *unstructured.Unstructured) {
	var es discoveryv1.EndpointSlice
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(o.Object, &es); err != nil {
		return
	}
	ed := &EndpointSliceDetail{
		AddressType: string(es.AddressType),
		ServiceName: es.Labels["kubernetes.io/service-name"],
	}
	for _, ep := range es.Endpoints {
		oe := Endpoint{Addresses: ep.Addresses}
		if ep.Conditions.Ready != nil {
			oe.Ready = ep.Conditions.Ready
		}
		if ep.NodeName != nil {
			oe.NodeName = *ep.NodeName
		}
		if ep.TargetRef != nil {
			oe.TargetName = ep.TargetRef.Name
			oe.TargetKind = ep.TargetRef.Kind
		}
		ed.Endpoints = append(ed.Endpoints, oe)
	}
	fr.Endpoints = ed
}

func parseImage(imageRef string) Image {
	named, err := reference.ParseNormalizedNamed(imageRef)
	if err != nil {
		return Image{Name: imageRef, FullName: imageRef}
	}
	named = reference.TagNameOnly(named)
	img := Image{
		Registry:   reference.Domain(named),
		Name:       reference.Path(named),
		Repository: named.Name(),
		FullName:   named.String(),
	}
	if tagged, ok := named.(reference.Tagged); ok {
		img.Version = tagged.Tag()
	}
	if digested, ok := named.(reference.Digested); ok {
		img.Digest = digested.Digest().String()
	}
	return img
}

func extractDigest(imageID string) string {
	if i := strings.LastIndex(imageID, "@"); i >= 0 {
		return imageID[i+1:]
	}
	return ""
}

func whitelistAnnotations(all map[string]string) map[string]string {
	if len(all) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range all {
		if annotationWhitelist[k] {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
