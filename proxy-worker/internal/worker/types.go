package worker

import (
	"fmt"
	"strings"
)

const APIVersion = "airlock.dev/v1alpha1"

type AirlockPolicy struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Metadata   Metadata `json:"metadata" yaml:"metadata"`
	Spec       Spec     `json:"spec" yaml:"spec"`
}

type Metadata struct {
	Name      string `json:"name" yaml:"name"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace"`
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
	Scheme   string        `json:"scheme,omitempty" yaml:"scheme"`
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

type ValidationError struct {
	Problems []string
}

func (e ValidationError) Error() string {
	return strings.Join(e.Problems, "; ")
}

func Compile(policy AirlockPolicy) (CompiledPolicy, error) {
	if err := Validate(policy); err != nil {
		return CompiledPolicy{}, err
	}
	return CompiledPolicy{
		Version:    policy.APIVersion,
		PolicyName: policy.Metadata.Name,
		Workload:   policy.Spec.Workload,
		Egress:     policy.Spec.Egress,
	}, nil
}

func Validate(policy AirlockPolicy) error {
	var problems []string
	if policy.APIVersion != APIVersion {
		problems = append(problems, fmt.Sprintf("apiVersion must be %q", APIVersion))
	}
	if policy.Kind != "AirlockPolicy" {
		problems = append(problems, "kind must be AirlockPolicy")
	}
	if strings.TrimSpace(policy.Metadata.Name) == "" {
		problems = append(problems, "metadata.name is required")
	}
	if strings.TrimSpace(policy.Spec.Workload.SPIFFEID) == "" {
		problems = append(problems, "spec.workload.spiffeId is required")
	}
	for i, rule := range policy.Spec.Egress {
		prefix := fmt.Sprintf("spec.egress[%d]", i)
		if strings.TrimSpace(rule.Name) == "" {
			problems = append(problems, prefix+".name is required")
		}
		if strings.TrimSpace(rule.Host) == "" {
			problems = append(problems, prefix+".host is required")
		}
		if rule.Scheme != "" && rule.Scheme != "http" && rule.Scheme != "https" {
			problems = append(problems, prefix+".scheme must be http or https")
		}
		if rule.Port > 65535 {
			problems = append(problems, prefix+".port must be between 1 and 65535")
		}
		for j, rewrite := range rule.Rewrites {
			rewritePrefix := fmt.Sprintf("%s.rewrites[%d]", prefix, j)
			if strings.TrimSpace(rewrite.Target) == "" {
				problems = append(problems, rewritePrefix+".target is required")
			}
			if rewrite.Target != "header" {
				problems = append(problems, rewritePrefix+".target must be header")
			}
			if strings.TrimSpace(rewrite.Name) == "" {
				problems = append(problems, rewritePrefix+".name is required")
			}
			validateSecretRef(rewritePrefix+".valueFrom", rewrite.ValueFrom, &problems)
		}
	}
	if len(problems) > 0 {
		return ValidationError{Problems: problems}
	}
	return nil
}

func validateSecretRef(prefix string, ref SecretRef, problems *[]string) {
	switch ref.Provider {
	case "env":
		if strings.TrimSpace(ref.Env) == "" {
			*problems = append(*problems, prefix+".env is required for env secrets")
		}
	case "file":
		if strings.TrimSpace(ref.File) == "" {
			*problems = append(*problems, prefix+".file is required for file secrets")
		}
	case "vault":
		if strings.TrimSpace(ref.Mount) == "" {
			*problems = append(*problems, prefix+".mount is required for vault secrets")
		}
		if ref.Engine != "kv-v2" {
			*problems = append(*problems, prefix+".engine must be kv-v2 for vault secrets")
		}
		if strings.TrimSpace(ref.Path) == "" {
			*problems = append(*problems, prefix+".path is required for vault secrets")
		}
		if strings.Contains(ref.Path, "*") {
			*problems = append(*problems, prefix+".path cannot contain wildcards")
		}
		if isUnsafeVaultPath(ref.Path) {
			*problems = append(*problems, prefix+".path cannot target sys/ or auth/")
		}
		if strings.TrimSpace(ref.Key) == "" {
			*problems = append(*problems, prefix+".key is required for vault secrets")
		}
	default:
		*problems = append(*problems, prefix+".provider must be one of env, file, vault")
	}
}

func isUnsafeVaultPath(path string) bool {
	clean := strings.Trim(strings.TrimSpace(path), "/")
	return clean == "sys" || clean == "auth" || strings.HasPrefix(clean, "sys/") || strings.HasPrefix(clean, "auth/")
}
