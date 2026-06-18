package policy

import (
	"fmt"
	"strings"

	airlockv1 "github.com/marcammann/airlock/api/v1alpha1"
	"github.com/marcammann/airlock/internal/vaultpath"
)

// CompiledPolicy is the validated worker policy document loaded by a proxy.
type CompiledPolicy = airlockv1.CompiledPolicy

// SecretRef is a secret reference embedded in a compiled policy rewrite.
type SecretRef = airlockv1.SecretRef

// ValidationError reports one or more compiled-policy validation failures.
type ValidationError struct {
	Problems []string
}

// Error formats validation failures as a single message.
func (e ValidationError) Error() string {
	return strings.Join(e.Problems, "; ")
}

// ValidateCompiledPolicy checks that a compiled policy is safe for proxy use.
func ValidateCompiledPolicy(policy CompiledPolicy) error {
	var problems []string
	if policy.Version != airlockv1.APIVersion {
		problems = append(problems, fmt.Sprintf("apiVersion must be %q", airlockv1.APIVersion))
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
		if vaultpath.IsUnsafe(ref.Path) {
			*problems = append(*problems, prefix+".path cannot target sys/ or auth/")
		}
		if strings.TrimSpace(ref.Key) == "" {
			*problems = append(*problems, prefix+".key is required for vault secrets")
		}
	default:
		*problems = append(*problems, prefix+".provider must be one of env, file, vault")
	}
}
