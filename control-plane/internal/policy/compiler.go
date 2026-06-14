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

func CompileWorkload(in AirlockWorkload, policies []AirlockPolicy) (CompiledPolicy, error) {
	return CompileWorkloadWithSecretProvider(in, policies, nil)
}

func CompileWorkloadWithSecretProvider(in AirlockWorkload, policies []AirlockPolicy, provider *SecretProviderConfig) (CompiledPolicy, error) {
	if err := ValidateWorkload(in); err != nil {
		return CompiledPolicy{}, err
	}
	var compiledProvider *CompiledSecretProvider

	if provider != nil {
		if err := ValidateSecretProviderConfig(*provider); err != nil {
			return CompiledPolicy{}, err
		}
		compiledProvider = compiledSecretProvider(in, *provider)
	}

	resolved, err := resolvePolicyRefs(in, policies)
	if err != nil {
		return CompiledPolicy{}, err
	}
	if provider != nil {
		resolved = applyProviderDefaults(resolved, *provider)
	}
	for _, input := range resolved {
		if err := Validate(input); err != nil {
			return CompiledPolicy{}, err
		}
	}
	egress, err := mergeEgressRules(resolved)
	if err != nil {
		return CompiledPolicy{}, err
	}

	return CompiledPolicy{
		Version:        in.APIVersion,
		PolicyName:     in.Metadata.Name,
		Workload:       in.Spec.Workload,
		SecretProvider: compiledProvider,
		Egress:         egress,
	}, nil
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
	if strings.Contains(in.Spec.Vault.Defaults.PathPrefix, "*") {
		problems = append(problems, "spec.vault.defaults.pathPrefix cannot contain wildcards")
	}
	if isUnsafeVaultPath(in.Spec.Vault.Defaults.PathPrefix) {
		problems = append(problems, "spec.vault.defaults.pathPrefix cannot target sys/ or auth/")
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
	for i, rule := range in.Spec.Egress {
		prefix := fmt.Sprintf("spec.egress[%d]", i)
		problems = append(problems, validateEgressRule(prefix, rule)...)
	}

	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

func ValidateWorkload(in AirlockWorkload) error {
	var problems []string

	if in.APIVersion != APIVersion {
		problems = append(problems, fmt.Sprintf("apiVersion must be %q", APIVersion))
	}
	if in.Kind != "AirlockWorkload" {
		problems = append(problems, "kind must be AirlockWorkload")
	}
	if strings.TrimSpace(in.Metadata.Name) == "" {
		problems = append(problems, "metadata.name is required")
	}
	if strings.TrimSpace(in.Spec.Workload.SPIFFEID) == "" {
		problems = append(problems, "spec.workload.spiffeId is required")
	}
	if len(in.Spec.PolicyRefs) == 0 {
		problems = append(problems, "spec.policyRefs is required")
	}
	seen := map[string]struct{}{}
	for i, ref := range in.Spec.PolicyRefs {
		prefix := fmt.Sprintf("spec.policyRefs[%d]", i)
		if strings.TrimSpace(ref.Name) == "" {
			problems = append(problems, prefix+".name is required")
		}
		key := policyRefKey(in.Metadata.Namespace, ref)
		if _, ok := seen[key]; ok {
			problems = append(problems, prefix+" duplicates policy ref "+key)
		}
		seen[key] = struct{}{}
	}

	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

func validateEgressRule(prefix string, rule EgressRule) []string {
	var problems []string
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
	return problems
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

func resolvePolicyRefs(workload AirlockWorkload, policies []AirlockPolicy) ([]AirlockPolicy, error) {
	byKey := map[string]AirlockPolicy{}
	var problems []string
	for _, candidate := range policies {
		if err := validatePolicyObject(candidate); err != nil {
			return nil, err
		}
		key := policyObjectKey(candidate)
		if existing, ok := byKey[key]; ok {
			problems = append(problems, fmt.Sprintf("policy %s duplicates %s/%s", key, existing.Metadata.Namespace, existing.Metadata.Name))
			continue
		}
		byKey[key] = candidate
	}

	out := make([]AirlockPolicy, 0, len(workload.Spec.PolicyRefs))
	for i, ref := range workload.Spec.PolicyRefs {
		key := policyRefKey(workload.Metadata.Namespace, ref)
		candidate, ok := byKey[key]
		if !ok {
			problems = append(problems, fmt.Sprintf("spec.policyRefs[%d] %s not found", i, key))
			continue
		}
		out = append(out, candidate)
	}
	if len(problems) > 0 {
		return nil, &ValidationError{Problems: problems}
	}
	return out, nil
}

func validatePolicyObject(in AirlockPolicy) error {
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
	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

func mergeEgressRules(policies []AirlockPolicy) ([]EgressRule, error) {
	var out []EgressRule
	seenRuleNames := map[string]PolicyRef{}
	var problems []string
	for _, input := range policies {
		source := PolicyRef{Name: input.Metadata.Name, Namespace: input.Metadata.Namespace}
		for _, rule := range input.Spec.Egress {
			ruleName := strings.TrimSpace(rule.Name)
			if existing, ok := seenRuleNames[ruleName]; ok {
				problems = append(problems, fmt.Sprintf("egress rule %q from policy %s duplicates policy %s", ruleName, policyDisplayName(source), policyDisplayName(existing)))
				continue
			}
			seenRuleNames[ruleName] = source
			copied := rule
			copied.SourcePolicy = &PolicyRef{Name: source.Name, Namespace: source.Namespace}
			out = append(out, copied)
		}
	}
	if len(problems) > 0 {
		return nil, &ValidationError{Problems: problems}
	}
	return out, nil
}

func applyProviderDefaults(in []AirlockPolicy, provider SecretProviderConfig) []AirlockPolicy {
	defaults := provider.Spec.Vault.Defaults
	out := make([]AirlockPolicy, len(in))
	copy(out, in)
	for policyIndex := range out {
		for i := range out[policyIndex].Spec.Egress {
			for j := range out[policyIndex].Spec.Egress[i].Rewrites {
				ref := &out[policyIndex].Spec.Egress[i].Rewrites[j].ValueFrom
				if ref.Provider != "vault" {
					continue
				}
				if ref.Mount == "" {
					ref.Mount = defaults.Mount
				}
				if ref.Engine == "" {
					ref.Engine = defaults.Engine
				}
				if strings.TrimSpace(defaults.PathPrefix) != "" && strings.TrimSpace(ref.Path) != "" {
					ref.Path = prefixedVaultPath(defaults.PathPrefix, ref.Path)
				}
			}
		}
	}
	return out
}

func prefixedVaultPath(prefix string, path string) string {
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	path = strings.Trim(strings.TrimSpace(path), "/")
	if prefix == "" {
		return path
	}
	if path == "" {
		return prefix
	}
	return prefix + "/" + path
}

func compiledSecretProvider(in AirlockWorkload, provider SecretProviderConfig) *CompiledSecretProvider {
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

func generatedVaultRole(in AirlockWorkload) string {
	namespace := strings.TrimSpace(in.Spec.Workload.Namespace)
	if namespace == "" {
		namespace = strings.TrimSpace(in.Metadata.Namespace)
	}
	if namespace == "" {
		namespace = "default"
	}
	return "airlock-" + dnsLabelPart(namespace) + "-" + dnsLabelPart(in.Metadata.Name)
}

func policyObjectKey(in AirlockPolicy) string {
	return namespacedKey(in.Metadata.Namespace, in.Metadata.Name)
}

func policyRefKey(defaultNamespace string, ref PolicyRef) string {
	namespace := strings.TrimSpace(ref.Namespace)
	if namespace == "" {
		namespace = strings.TrimSpace(defaultNamespace)
	}
	return namespacedKey(namespace, strings.TrimSpace(ref.Name))
}

func policyDisplayName(ref PolicyRef) string {
	if strings.TrimSpace(ref.Namespace) == "" {
		return strings.TrimSpace(ref.Name)
	}
	return strings.TrimSpace(ref.Namespace) + "/" + strings.TrimSpace(ref.Name)
}

func namespacedKey(namespace string, name string) string {
	return strings.TrimSpace(namespace) + "/" + strings.TrimSpace(name)
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
