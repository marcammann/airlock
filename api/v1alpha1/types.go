// Package v1alpha1 defines the Airlock Kubernetes API types.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// APIVersion is the Kubernetes API version used by Airlock custom resources.
const APIVersion = "airlock.dev/v1alpha1"

// SchemeGroupVersion identifies the Airlock Kubernetes API group and version.
var SchemeGroupVersion = schema.GroupVersion{Group: "airlock.dev", Version: "v1alpha1"}

// SchemeBuilder registers Airlock API types with a Kubernetes runtime scheme.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme registers Airlock API types with a Kubernetes runtime scheme.
var AddToScheme = SchemeBuilder.AddToScheme

// Metadata is Kubernetes object metadata for Airlock resources.
type Metadata = metav1.ObjectMeta

// AirlockPolicy defines reusable egress rules that can be assigned to workloads.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=airlockpolicies,scope=Namespaced,shortName=alp
// +kubebuilder:subresource:status
type AirlockPolicy struct {
	metav1.TypeMeta `json:",inline" yaml:",inline"`
	Metadata        `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	Spec   PolicySpec `json:"spec" yaml:"spec"`
	Status Status     `json:"status,omitempty" yaml:"status,omitempty"`
}

// UnmarshalYAML decodes an AirlockPolicy from Kubernetes-style YAML.
func (in *AirlockPolicy) UnmarshalYAML(unmarshal func(any) error) error {
	var out struct {
		APIVersion string     `yaml:"apiVersion"`
		Kind       string     `yaml:"kind"`
		Metadata   Metadata   `yaml:"metadata"`
		Spec       PolicySpec `yaml:"spec"`
		Status     Status     `yaml:"status"`
	}
	if err := unmarshal(&out); err != nil {
		return err
	}
	in.TypeMeta = metav1.TypeMeta{APIVersion: out.APIVersion, Kind: out.Kind}
	in.Metadata = out.Metadata
	in.Spec = out.Spec
	in.Status = out.Status
	return nil
}

// AirlockPolicyList contains a list of AirlockPolicy objects.
//
// +kubebuilder:object:root=true
type AirlockPolicyList struct {
	metav1.TypeMeta `json:",inline" yaml:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	Items []AirlockPolicy `json:"items" yaml:"items"`
}

// AirlockWorkload binds one workload identity to one or more Airlock policies.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=airlockworkloads,scope=Namespaced,shortName=alw
// +kubebuilder:subresource:status
type AirlockWorkload struct {
	metav1.TypeMeta `json:",inline" yaml:",inline"`
	Metadata        `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	Spec   WorkloadSpec `json:"spec" yaml:"spec"`
	Status Status       `json:"status,omitempty" yaml:"status,omitempty"`
}

// UnmarshalYAML decodes an AirlockWorkload from Kubernetes-style YAML.
func (in *AirlockWorkload) UnmarshalYAML(unmarshal func(any) error) error {
	var out struct {
		APIVersion string       `yaml:"apiVersion"`
		Kind       string       `yaml:"kind"`
		Metadata   Metadata     `yaml:"metadata"`
		Spec       WorkloadSpec `yaml:"spec"`
		Status     Status       `yaml:"status"`
	}
	if err := unmarshal(&out); err != nil {
		return err
	}
	in.TypeMeta = metav1.TypeMeta{APIVersion: out.APIVersion, Kind: out.Kind}
	in.Metadata = out.Metadata
	in.Spec = out.Spec
	in.Status = out.Status
	return nil
}

// AirlockWorkloadList contains a list of AirlockWorkload objects.
//
// +kubebuilder:object:root=true
type AirlockWorkloadList struct {
	metav1.TypeMeta `json:",inline" yaml:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	Items []AirlockWorkload `json:"items" yaml:"items"`
}

// PolicySpec describes the reusable egress rules in an AirlockPolicy.
type PolicySpec struct {
	Egress []EgressRule `json:"egress" yaml:"egress"`
}

// WorkloadSpec describes the workload identity, assigned policies, and optional secret provider.
type WorkloadSpec struct {
	SecretProviderRef SecretProviderRef `json:"secretProviderRef,omitempty" yaml:"secretProviderRef"`
	Workload          WorkloadIdentity  `json:"workload" yaml:"workload"`
	PolicyRefs        []PolicyRef       `json:"policyRefs" yaml:"policyRefs"`
}

// SecretProviderRef references a SecretProviderConfig by name and optional namespace.
type SecretProviderRef struct {
	Name      string `json:"name,omitempty" yaml:"name"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace"`
}

// PolicyRef references an AirlockPolicy by name and optional namespace.
type PolicyRef struct {
	Name      string `json:"name" yaml:"name"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}

// WorkloadIdentity describes the runtime identity that a proxy worker represents.
type WorkloadIdentity struct {
	SPIFFEID       string `json:"spiffeId,omitempty" yaml:"spiffeId"`
	Namespace      string `json:"namespace,omitempty" yaml:"namespace"`
	ServiceAccount string `json:"serviceAccount,omitempty" yaml:"serviceAccount"`
}

// EgressRule describes one allowed outbound destination and optional request rewrites.
type EgressRule struct {
	Name   string `json:"name" yaml:"name"`
	Scheme string `json:"scheme" yaml:"scheme"`
	Host   string `json:"host" yaml:"host"`
	// Port matches a destination port. Port 0 matches any destination port.
	Port         uint32        `json:"port,omitempty" yaml:"port"`
	Rewrites     []RewriteRule `json:"rewrites,omitempty" yaml:"rewrites"`
	SourcePolicy *PolicyRef    `json:"sourcePolicy,omitempty" yaml:"sourcePolicy,omitempty"`
}

// RewriteRule describes a header mutation applied before forwarding an allowed request.
type RewriteRule struct {
	Target        string    `json:"target" yaml:"target"`
	Name          string    `json:"name" yaml:"name"`
	ValueTemplate string    `json:"valueTemplate,omitempty" yaml:"valueTemplate"`
	ValueFrom     SecretRef `json:"valueFrom" yaml:"valueFrom"`
}

// SecretRef describes where a rewrite secret value should be resolved from.
type SecretRef struct {
	Provider string `json:"provider" yaml:"provider"`
	Name     string `json:"name,omitempty" yaml:"name"`
	Mount    string `json:"mount,omitempty" yaml:"mount"`
	Engine   string `json:"engine,omitempty" yaml:"engine"`
	Path     string `json:"path,omitempty" yaml:"path"`
	Key      string `json:"key,omitempty" yaml:"key"`
	Env      string `json:"env,omitempty" yaml:"env"`
	File     string `json:"file,omitempty" yaml:"file"`
}

// CompiledPolicy is the single effective policy document consumed by a proxy worker.
type CompiledPolicy struct {
	Version        string                  `json:"version" yaml:"version"`
	PolicyName     string                  `json:"policyName" yaml:"policyName"`
	Workload       WorkloadIdentity        `json:"workload" yaml:"workload"`
	SecretProvider *CompiledSecretProvider `json:"secretProvider,omitempty" yaml:"secretProvider,omitempty"`
	Egress         []EgressRule            `json:"egress" yaml:"egress"`
}

// CompiledSecretProvider is the worker-facing secret provider configuration.
type CompiledSecretProvider struct {
	Provider string                 `json:"provider" yaml:"provider"`
	Vault    *CompiledVaultProvider `json:"vault,omitempty" yaml:"vault,omitempty"`
}

// CompiledVaultProvider is the worker-facing Vault configuration.
type CompiledVaultProvider struct {
	Address   string `json:"address" yaml:"address"`
	AuthMount string `json:"authMount" yaml:"authMount"`
	Audience  string `json:"audience" yaml:"audience"`
	Role      string `json:"role" yaml:"role"`
}

// SecretProviderConfig defines environment-specific secret backend configuration.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=secretproviderconfigs,scope=Namespaced,shortName=spc
// +kubebuilder:subresource:status
type SecretProviderConfig struct {
	metav1.TypeMeta `json:",inline" yaml:",inline"`
	Metadata        `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	Spec   SecretProviderConfigSpec `json:"spec" yaml:"spec"`
	Status Status                   `json:"status,omitempty" yaml:"status,omitempty"`
}

// UnmarshalYAML decodes a SecretProviderConfig from Kubernetes-style YAML.
func (in *SecretProviderConfig) UnmarshalYAML(unmarshal func(any) error) error {
	var out struct {
		APIVersion string                   `yaml:"apiVersion"`
		Kind       string                   `yaml:"kind"`
		Metadata   Metadata                 `yaml:"metadata"`
		Spec       SecretProviderConfigSpec `yaml:"spec"`
		Status     Status                   `yaml:"status"`
	}
	if err := unmarshal(&out); err != nil {
		return err
	}
	in.TypeMeta = metav1.TypeMeta{APIVersion: out.APIVersion, Kind: out.Kind}
	in.Metadata = out.Metadata
	in.Spec = out.Spec
	in.Status = out.Status
	return nil
}

// SecretProviderConfigList contains a list of SecretProviderConfig objects.
//
// +kubebuilder:object:root=true
type SecretProviderConfigList struct {
	metav1.TypeMeta `json:",inline" yaml:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	Items []SecretProviderConfig `json:"items" yaml:"items"`
}

// SecretProviderConfigSpec describes a supported secret backend and its defaults.
type SecretProviderConfigSpec struct {
	Provider string            `json:"provider" yaml:"provider"`
	Vault    VaultProviderSpec `json:"vault" yaml:"vault"`
}

// VaultProviderSpec configures Vault as an Airlock secret provider.
type VaultProviderSpec struct {
	Address  string                `json:"address" yaml:"address"`
	Auth     VaultAuthSpec         `json:"auth" yaml:"auth"`
	Defaults VaultProviderDefaults `json:"defaults,omitempty" yaml:"defaults"`
}

// VaultAuthSpec describes how proxy workers authenticate to Vault.
type VaultAuthSpec struct {
	Method   string `json:"method" yaml:"method"`
	Mount    string `json:"mount" yaml:"mount"`
	Audience string `json:"audience" yaml:"audience"`
}

// VaultProviderDefaults supplies defaults for policy secret references.
type VaultProviderDefaults struct {
	Engine     string `json:"engine,omitempty" yaml:"engine"`
	Mount      string `json:"mount,omitempty" yaml:"mount"`
	PathPrefix string `json:"pathPrefix,omitempty" yaml:"pathPrefix"`
}

// Status records observed reconciliation state for Airlock resources.
type Status struct {
	ObservedGeneration int64             `json:"observedGeneration,omitempty" yaml:"observedGeneration,omitempty"`
	PolicyHash         string            `json:"policyHash,omitempty" yaml:"policyHash,omitempty"`
	Spire              SubsystemStatus   `json:"spire,omitempty" yaml:"spire,omitempty"`
	Vault              SubsystemStatus   `json:"vault,omitempty" yaml:"vault,omitempty"`
	Conditions         []StatusCondition `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}

// SubsystemStatus records readiness for an Airlock-managed subsystem.
type SubsystemStatus struct {
	Ready bool `json:"ready" yaml:"ready"`
}

// StatusCondition records one status condition on an Airlock resource.
type StatusCondition struct {
	Type    string `json:"type" yaml:"type"`
	Status  string `json:"status" yaml:"status"`
	Reason  string `json:"reason,omitempty" yaml:"reason,omitempty"`
	Message string `json:"message,omitempty" yaml:"message,omitempty"`
}

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(
		SchemeGroupVersion,
		&AirlockPolicy{},
		&AirlockPolicyList{},
		&AirlockWorkload{},
		&AirlockWorkloadList{},
		&SecretProviderConfig{},
		&SecretProviderConfigList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// DeepCopyObject returns a runtime.Object copy of the policy.
func (in *AirlockPolicy) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(AirlockPolicy)
	*out = *in
	out.Metadata = *in.Metadata.DeepCopy()
	out.Spec.Egress = deepCopyEgressRules(in.Spec.Egress)
	out.Status = deepCopyStatus(in.Status)
	return out
}

// DeepCopyObject returns a runtime.Object copy of the policy list.
func (in *AirlockPolicyList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(AirlockPolicyList)
	*out = *in
	out.ListMeta = *in.ListMeta.DeepCopy()
	out.Items = make([]AirlockPolicy, len(in.Items))
	for i := range in.Items {
		out.Items[i] = *in.Items[i].DeepCopyObject().(*AirlockPolicy)
	}
	return out
}

// DeepCopyObject returns a runtime.Object copy of the workload.
func (in *AirlockWorkload) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(AirlockWorkload)
	*out = *in
	out.Metadata = *in.Metadata.DeepCopy()
	out.Spec.PolicyRefs = append([]PolicyRef(nil), in.Spec.PolicyRefs...)
	out.Status = deepCopyStatus(in.Status)
	return out
}

// DeepCopyObject returns a runtime.Object copy of the workload list.
func (in *AirlockWorkloadList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(AirlockWorkloadList)
	*out = *in
	out.ListMeta = *in.ListMeta.DeepCopy()
	out.Items = make([]AirlockWorkload, len(in.Items))
	for i := range in.Items {
		out.Items[i] = *in.Items[i].DeepCopyObject().(*AirlockWorkload)
	}
	return out
}

// DeepCopyObject returns a runtime.Object copy of the secret provider config.
func (in *SecretProviderConfig) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(SecretProviderConfig)
	*out = *in
	out.Metadata = *in.Metadata.DeepCopy()
	out.Status = deepCopyStatus(in.Status)
	return out
}

// DeepCopyObject returns a runtime.Object copy of the secret provider config list.
func (in *SecretProviderConfigList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(SecretProviderConfigList)
	*out = *in
	out.ListMeta = *in.ListMeta.DeepCopy()
	out.Items = make([]SecretProviderConfig, len(in.Items))
	for i := range in.Items {
		out.Items[i] = *in.Items[i].DeepCopyObject().(*SecretProviderConfig)
	}
	return out
}

func deepCopyEgressRules(in []EgressRule) []EgressRule {
	if in == nil {
		return nil
	}
	out := make([]EgressRule, len(in))
	copy(out, in)
	for i := range out {
		out[i].Rewrites = append([]RewriteRule(nil), in[i].Rewrites...)
		if in[i].SourcePolicy != nil {
			out[i].SourcePolicy = new(PolicyRef)
			*out[i].SourcePolicy = *in[i].SourcePolicy
		}
	}
	return out
}

func deepCopyStatus(in Status) Status {
	out := in
	out.Conditions = append([]StatusCondition(nil), in.Conditions...)
	return out
}
