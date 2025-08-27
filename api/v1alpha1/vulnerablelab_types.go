/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VulnerableLabSpec defines the desired state of VulnerableLab.
type VulnerableLabSpec struct {
	// +optional
	// +kubebuilder:validation:Enum=K01;K02;K03;K04;K06;K07;K08;K09;K10
	Vulnerability string `json:"vulnerability,omitempty"`
}

// VulnerableLabStatus defines the observed state of VulnerableLab.
type VulnerableLabStatus struct {
	// The chosen vulnerability for this instance
	// +optional
	ChosenVulnerability string `json:"chosenVulnerability,omitempty"`
	// The specific target for the vulnerability (e.g., a deployment name for K01)
	// +optional
	TargetResource string `json:"targetResource,omitempty"`
	// State of the lab (Vulnerable, Remediated, Error)
	// +optional
	State string `json:"state,omitempty"`
	// A message for the student
	// +optional
	Message string `json:"message,omitempty"`
}

const (
	StateVulnerable  = "Vulnerable"
	StateRemediated  = "Remediated"
	StateError       = "Error"
	StateInitialized = "Initialized"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// VulnerableLab is the Schema for the vulnerablelabs API.
type VulnerableLab struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VulnerableLabSpec   `json:"spec,omitempty"`
	Status VulnerableLabStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VulnerableLabList contains a list of VulnerableLab.
type VulnerableLabList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VulnerableLab `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VulnerableLab{}, &VulnerableLabList{})
}
