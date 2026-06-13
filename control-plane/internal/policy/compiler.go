package policy

import (
	"errors"
	"fmt"
	"strings"
)

const APIVersion = "airlock.dev/v1alpha1"

var allowedSecretProviders = map[string]struct{}{
	"env":   {},
	"file":  {},
	"vault": {},
}

type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return strings.Join(e.Problems, "; ")
}

func Compile(in AirlockPolicy) (CompiledPolicy, error) {
	if err := Validate(in); err != nil {
		return CompiledPolicy{}, err
	}

	return CompiledPolicy{
		Version:    in.APIVersion,
		PolicyName: in.Metadata.Name,
		Workload:   in.Spec.Workload,
		Egress:     in.Spec.Egress,
	}, nil
}

func CompileWithSecretProvider(in AirlockPolicy, provider *SecretProviderConfig) (CompiledPolicy, error) {
	resolved := in
	var compiledProvider *CompiledSecretProvider

	if provider != nil {
		if err := ValidateSecretProviderConfig(*provider); err != nil {
			return CompiledPolicy{}, err
		}
		resolved = applyProviderDefaults(resolved, *provider)
		compiledProvider = compiledSecretProvider(resolved, *provider)
	}

	compiled, err := Compile(resolved)
	if err != nil {
		return CompiledPolicy{}, err
	}
	compiled.SecretProvider = compiledProvider
	return compiled, nil
}

func ValidateSecretProviderConfig(in SecretProviderConfig) error {
	var problems []string

	if in.APIVersion != APIVersion {
		problems = append(problems, fmt.Sprintf("apiVersion must be %q", APIVersion))
	}
	if in.Kind != "SecretProviderConfig" {
		problems = append(problems, "kind must be SecretProviderConfig")
	}
	if strings.TrimSpace(in.Metadata.Name) == "" {
		problems = append(problems, "metadata.name is required")
	}
	if in.Spec.Provider != "vault" {
		problems = append(problems, "spec.provider must be vault")
	}
	if strings.TrimSpace(in.Spec.Vault.Address) == "" {
		problems = append(problems, "spec.vault.address is required")
	}
	if in.Spec.Vault.Auth.Method != "spiffe-jwt" {
		problems = append(problems, "spec.vault.auth.method must be spiffe-jwt")
	}
	if strings.TrimSpace(in.Spec.Vault.Auth.Mount) == "" {
		problems = append(problems, "spec.vault.auth.mount is required")
	}
	if strings.TrimSpace(in.Spec.Vault.Auth.Audience) == "" {
		problems = append(problems, "spec.vault.auth.audience is required")
	}
	if in.Spec.Vault.Defaults.Engine != "" && in.Spec.Vault.Defaults.Engine != "kv-v2" {
		problems = append(problems, "spec.vault.defaults.engine must be kv-v2")
	}

	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

func Validate(in AirlockPolicy) error {
	var problems []string

	if in.APIVersion != APIVersion {
		problems = append(problems, fmt.Sprintf("apiVersion must be %q", APIVersion))
	}
	if in.Kind != "AirlockPolicy" {
		problems = append(problems, "kind must be AirlockPolicy")
	}
	if strings.TrimSpace(in.Metadata.Name) == "" {
		problems = append(problems, "metadata.name is required")
	}
	if strings.TrimSpace(in.Spec.Workload.SPIFFEID) == "" {
		problems = append(problems, "spec.workload.spiffeId is required")
	}
	for i, rule := range in.Spec.Egress {
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
			problems = append(problems, validateSecretRef(rewritePrefix+".valueFrom", rewrite.ValueFrom)...)
		}
	}

	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

func validateSecretRef(prefix string, ref SecretRef) []string {
	var problems []string

	if _, ok := allowedSecretProviders[ref.Provider]; !ok {
		problems = append(problems, prefix+".provider must be one of env, file, vault")
		return problems
	}

	switch ref.Provider {
	case "env":
		if strings.TrimSpace(ref.Env) == "" {
			problems = append(problems, prefix+".env is required for env secrets")
		}
	case "file":
		if strings.TrimSpace(ref.File) == "" {
			problems = append(problems, prefix+".file is required for file secrets")
		}
	case "vault":
		if strings.TrimSpace(ref.Mount) == "" {
			problems = append(problems, prefix+".mount is required for vault secrets")
		}
		if ref.Engine != "kv-v2" {
			problems = append(problems, prefix+".engine must be kv-v2 for vault secrets")
		}
		if strings.TrimSpace(ref.Path) == "" {
			problems = append(problems, prefix+".path is required for vault secrets")
		}
		if strings.Contains(ref.Path, "*") {
			problems = append(problems, prefix+".path cannot contain wildcards")
		}
		if isUnsafeVaultPath(ref.Path) {
			problems = append(problems, prefix+".path cannot target sys/ or auth/")
		}
		if strings.TrimSpace(ref.Key) == "" {
			problems = append(problems, prefix+".key is required for vault secrets")
		}
	}

	return problems
}

func applyProviderDefaults(in AirlockPolicy, provider SecretProviderConfig) AirlockPolicy {
	defaults := provider.Spec.Vault.Defaults
	for i := range in.Spec.Egress {
		for j := range in.Spec.Egress[i].Rewrites {
			ref := &in.Spec.Egress[i].Rewrites[j].ValueFrom
			if ref.Provider != "vault" {
				continue
			}
			if ref.Mount == "" {
				ref.Mount = defaults.Mount
			}
			if ref.Engine == "" {
				ref.Engine = defaults.Engine
			}
		}
	}
	return in
}

func compiledSecretProvider(in AirlockPolicy, provider SecretProviderConfig) *CompiledSecretProvider {
	return &CompiledSecretProvider{
		Provider: "vault",
		Vault: &CompiledVaultProvider{
			Address:   provider.Spec.Vault.Address,
			AuthMount: provider.Spec.Vault.Auth.Mount,
			Audience:  provider.Spec.Vault.Auth.Audience,
			Role:      generatedVaultRole(in),
		},
	}
}

func generatedVaultRole(in AirlockPolicy) string {
	namespace := strings.TrimSpace(in.Spec.Workload.Namespace)
	if namespace == "" {
		namespace = strings.TrimSpace(in.Metadata.Namespace)
	}
	if namespace == "" {
		namespace = "default"
	}
	return "airlock-" + dnsLabelPart(namespace) + "-" + dnsLabelPart(in.Metadata.Name)
}

func dnsLabelPart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var out strings.Builder
	lastDash := false
	for _, ch := range value {
		valid := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
		if valid {
			out.WriteRune(ch)
			lastDash = false
			continue
		}
		if !lastDash {
			out.WriteByte('-')
			lastDash = true
		}
	}
	clean := strings.Trim(out.String(), "-")
	if clean == "" {
		return "default"
	}
	return clean
}

func isUnsafeVaultPath(path string) bool {
	clean := strings.Trim(strings.TrimSpace(path), "/")
	return clean == "sys" || clean == "auth" || strings.HasPrefix(clean, "sys/") || strings.HasPrefix(clean, "auth/")
}

func IsValidationError(err error) bool {
	var target *ValidationError
	return errors.As(err, &target)
}
