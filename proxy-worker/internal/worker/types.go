package worker

import (
	"fmt"
	"strings"
)

const APIVersion = "airlock.dev/v1alpha1"

type WorkloadIdentity struct {
	SPIFFEID       string `json:"spiffeId,omitempty" yaml:"spiffeId"`
	Namespace      string `json:"namespace,omitempty" yaml:"namespace"`
	ServiceAccount string `json:"serviceAccount,omitempty" yaml:"serviceAccount"`
}

type PolicyRef struct {
	Name      string `json:"name" yaml:"name"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}

type EgressRule struct {
	Name         string        `json:"name" yaml:"name"`
	Scheme       string        `json:"scheme,omitempty" yaml:"scheme"`
	Host         string        `json:"host" yaml:"host"`
	Port         uint32        `json:"port,omitempty" yaml:"port"`
	Rewrites     []RewriteRule `json:"rewrites,omitempty" yaml:"rewrites"`
	SourcePolicy *PolicyRef    `json:"sourcePolicy,omitempty" yaml:"sourcePolicy,omitempty"`
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
	Version        string                  `json:"version" yaml:"version"`
	PolicyName     string                  `json:"policyName" yaml:"policyName"`
	Workload       WorkloadIdentity        `json:"workload" yaml:"workload"`
	SecretProvider *CompiledSecretProvider `json:"secretProvider,omitempty" yaml:"secretProvider,omitempty"`
	Egress         []EgressRule            `json:"egress" yaml:"egress"`
}

type CompiledSecretProvider struct {
	Provider string                 `json:"provider" yaml:"provider"`
	Vault    *CompiledVaultProvider `json:"vault,omitempty" yaml:"vault,omitempty"`
}

type CompiledVaultProvider struct {
	Address   string `json:"address" yaml:"address"`
	AuthMount string `json:"authMount" yaml:"authMount"`
	Audience  string `json:"audience" yaml:"audience"`
	Role      string `json:"role" yaml:"role"`
}

type ValidationError struct {
	Problems []string
}

func (e ValidationError) Error() string {
	return strings.Join(e.Problems, "; ")
}

func ValidateCompiledPolicy(policy CompiledPolicy) error {
	var problems []string
	if policy.Version != APIVersion {
		problems = append(problems, fmt.Sprintf("apiVersion must be %q", APIVersion))
	}
	if strings.TrimSpace(policy.PolicyName) == "" {
		problems = append(problems, "policyName is required")
	}
	if strings.TrimSpace(policy.Workload.SPIFFEID) == "" {
		problems = append(problems, "workload.spiffeId is required")
	}
	for i, rule := range policy.Egress {
		prefix := fmt.Sprintf("egress[%d]", i)
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
