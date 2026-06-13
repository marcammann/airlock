package policy

type AirlockPolicy struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Metadata   Metadata `json:"metadata" yaml:"metadata"`
	Spec       Spec     `json:"spec" yaml:"spec"`
	Status     Status   `json:"status,omitempty" yaml:"status,omitempty"`
}

type Metadata struct {
	Name            string `json:"name" yaml:"name"`
	Namespace       string `json:"namespace,omitempty" yaml:"namespace"`
	Generation      int64  `json:"generation,omitempty" yaml:"generation,omitempty"`
	ResourceVersion string `json:"resourceVersion,omitempty" yaml:"resourceVersion,omitempty"`
}

type Spec struct {
	SecretProviderRef SecretProviderRef `json:"secretProviderRef,omitempty" yaml:"secretProviderRef"`
	Workload          WorkloadIdentity  `json:"workload" yaml:"workload"`
	Egress            []EgressRule      `json:"egress" yaml:"egress"`
}

type SecretProviderRef struct {
	Name      string `json:"name,omitempty" yaml:"name"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace"`
}

type WorkloadIdentity struct {
	SPIFFEID       string `json:"spiffeId,omitempty" yaml:"spiffeId"`
	Namespace      string `json:"namespace,omitempty" yaml:"namespace"`
	ServiceAccount string `json:"serviceAccount,omitempty" yaml:"serviceAccount"`
}

type EgressRule struct {
	Name     string        `json:"name" yaml:"name"`
	Scheme   string        `json:"scheme" yaml:"scheme"`
	Host     string        `json:"host" yaml:"host"`
	Port     uint32        `json:"port,omitempty" yaml:"port"`
	Rewrites []RewriteRule `json:"rewrites,omitempty" yaml:"rewrites"`
}

type RewriteRule struct {
	Target        string    `json:"target" yaml:"target"`
	Name          string    `json:"name" yaml:"name"`
	ValueTemplate string    `json:"valueTemplate,omitempty" yaml:"valueTemplate"`
	ValueFrom     SecretRef `json:"valueFrom" yaml:"valueFrom"`
}

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

type CompiledPolicy struct {
	Version        string                  `json:"version"`
	PolicyName     string                  `json:"policyName"`
	Workload       WorkloadIdentity        `json:"workload"`
	SecretProvider *CompiledSecretProvider `json:"secretProvider,omitempty"`
	Egress         []EgressRule            `json:"egress"`
}

type CompiledSecretProvider struct {
	Provider string                 `json:"provider"`
	Vault    *CompiledVaultProvider `json:"vault,omitempty"`
}

type CompiledVaultProvider struct {
	Address   string `json:"address"`
	AuthMount string `json:"authMount"`
	Audience  string `json:"audience"`
	Role      string `json:"role"`
}

type SecretProviderConfig struct {
	APIVersion string                   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                   `json:"kind" yaml:"kind"`
	Metadata   Metadata                 `json:"metadata" yaml:"metadata"`
	Spec       SecretProviderConfigSpec `json:"spec" yaml:"spec"`
}

type SecretProviderConfigSpec struct {
	Provider string            `json:"provider" yaml:"provider"`
	Vault    VaultProviderSpec `json:"vault" yaml:"vault"`
}

type VaultProviderSpec struct {
	Address  string                `json:"address" yaml:"address"`
	Auth     VaultAuthSpec         `json:"auth" yaml:"auth"`
	Defaults VaultProviderDefaults `json:"defaults,omitempty" yaml:"defaults"`
}

type VaultAuthSpec struct {
	Method   string `json:"method" yaml:"method"`
	Mount    string `json:"mount" yaml:"mount"`
	Audience string `json:"audience" yaml:"audience"`
}

type VaultProviderDefaults struct {
	Engine string `json:"engine,omitempty" yaml:"engine"`
	Mount  string `json:"mount,omitempty" yaml:"mount"`
}

type Status struct {
	ObservedGeneration int64             `json:"observedGeneration,omitempty" yaml:"observedGeneration,omitempty"`
	PolicyHash         string            `json:"policyHash,omitempty" yaml:"policyHash,omitempty"`
	Spire              SubsystemStatus   `json:"spire,omitempty" yaml:"spire,omitempty"`
	Vault              SubsystemStatus   `json:"vault,omitempty" yaml:"vault,omitempty"`
	Conditions         []StatusCondition `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}

type SubsystemStatus struct {
	Ready bool `json:"ready" yaml:"ready"`
}

type StatusCondition struct {
	Type    string `json:"type" yaml:"type"`
	Status  string `json:"status" yaml:"status"`
	Reason  string `json:"reason,omitempty" yaml:"reason,omitempty"`
	Message string `json:"message,omitempty" yaml:"message,omitempty"`
}
