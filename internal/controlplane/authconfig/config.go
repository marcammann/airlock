package authconfig

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	controlauth "github.com/marcammann/airlock/internal/controlplane/auth"
	controlenrollment "github.com/marcammann/airlock/internal/controlplane/enrollment"
	"gopkg.in/yaml.v3"
)

// RuntimeConfig contains the auth components built from YAML configuration.
type RuntimeConfig struct {
	AdminAuthenticator      *controlauth.AuthenticatorChain
	AdminRBAC               *controlauth.RBACAuthorizer
	EnrollmentAuthenticator *controlauth.AuthenticatorChain
	EnrollmentAuthorizer    *controlenrollment.Authorizer
	EnrollmentDefaultTTL    time.Duration
	EnrollmentMaxTTL        time.Duration
}

// ConfigFile is the top-level auth configuration file.
type ConfigFile struct {
	Version string     `yaml:"version"`
	Auth    YAMLConfig `yaml:"auth"`
}

// YAMLConfig groups admin and enrollment auth configuration.
type YAMLConfig struct {
	Admin      AdminYAMLConfig      `yaml:"admin"`
	Enrollment EnrollmentYAMLConfig `yaml:"enrollment"`
}

// AdminYAMLConfig configures admin API authentication and RBAC.
type AdminYAMLConfig struct {
	Providers []ProviderYAMLConfig `yaml:"providers"`
	RBAC      RBACYAMLConfig       `yaml:"rbac"`
}

// EnrollmentYAMLConfig configures enrollment authentication and grants.
type EnrollmentYAMLConfig struct {
	Providers  []ProviderYAMLConfig  `yaml:"providers"`
	Grants     []EnrollmentGrantYAML `yaml:"grants"`
	DefaultTTL string                `yaml:"defaultTTL"`
	MaxTTL     string                `yaml:"maxTTL"`
}

// ProviderYAMLConfig configures one auth provider.
type ProviderYAMLConfig struct {
	Name           string            `yaml:"name"`
	Type           string            `yaml:"type"`
	Keys           []APIKeyYAML      `yaml:"keys"`
	Issuer         string            `yaml:"issuer"`
	Audience       string            `yaml:"audience"`
	JWKSURL        string            `yaml:"jwksUrl"`
	GroupsClaim    string            `yaml:"groupsClaim"`
	RolesClaim     string            `yaml:"rolesClaim"`
	RequiredClaims map[string]string `yaml:"requiredClaims"`
}

// APIKeyYAML configures one API key principal.
type APIKeyYAML struct {
	ID     string   `yaml:"id"`
	Hash   string   `yaml:"hash"`
	Value  string   `yaml:"value"`
	Env    string   `yaml:"env"`
	File   string   `yaml:"file"`
	Groups []string `yaml:"groups"`
	Roles  []string `yaml:"roles"`
}

// RBACYAMLConfig configures admin role bindings and role definitions.
type RBACYAMLConfig struct {
	RoleBindings []RoleBindingYAML         `yaml:"roleBindings"`
	Roles        map[string]RoleYAMLConfig `yaml:"roles"`
}

// RoleBindingYAML maps a subject to one or more roles.
type RoleBindingYAML struct {
	Subject string   `yaml:"subject"`
	Roles   []string `yaml:"roles"`
}

// RoleYAMLConfig lists permissions attached to a role.
type RoleYAMLConfig struct {
	Permissions []string `yaml:"permissions"`
}

// EnrollmentGrantYAML grants enrollment permissions for selected workloads.
type EnrollmentGrantYAML struct {
	Subject     string                   `yaml:"subject"`
	Subjects    []string                 `yaml:"subjects"`
	Permissions []string                 `yaml:"permissions"`
	Workloads   []EnrollmentWorkloadYAML `yaml:"workloads"`
}

// EnrollmentWorkloadYAML selects one workload for enrollment authorization.
type EnrollmentWorkloadYAML struct {
	Namespace string `yaml:"namespace"`
	Name      string `yaml:"name"`
}

// LoadRuntimeConfig reads an auth YAML file and builds runtime auth components.
func LoadRuntimeConfig(ctx context.Context, path string) (RuntimeConfig, error) {
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("read auth config: %w", err)
	}
	var config ConfigFile
	if err := yaml.Unmarshal(data, &config); err != nil {
		return RuntimeConfig{}, fmt.Errorf("parse auth config: %w", err)
	}
	return BuildRuntimeConfig(ctx, config)
}

// BuildRuntimeConfig builds runtime auth components from parsed configuration.
func BuildRuntimeConfig(ctx context.Context, config ConfigFile) (RuntimeConfig, error) {
	var out RuntimeConfig
	var err error

	out.AdminAuthenticator, err = buildAuthenticatorChain(ctx, config.Auth.Admin.Providers)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("admin auth: %w", err)
	}
	if hasRBACConfig(config.Auth.Admin.RBAC) {
		out.AdminRBAC, err = buildRBACAuthorizer(config.Auth.Admin.RBAC)
		if err != nil {
			return RuntimeConfig{}, fmt.Errorf("admin rbac: %w", err)
		}
	}

	out.EnrollmentAuthenticator, err = buildAuthenticatorChain(ctx, config.Auth.Enrollment.Providers)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("enrollment auth: %w", err)
	}
	if len(config.Auth.Enrollment.Grants) > 0 {
		out.EnrollmentAuthorizer, err = buildEnrollmentAuthorizer(config.Auth.Enrollment.Grants)
		if err != nil {
			return RuntimeConfig{}, fmt.Errorf("enrollment grants: %w", err)
		}
	}
	out.EnrollmentDefaultTTL, err = parseOptionalDuration(config.Auth.Enrollment.DefaultTTL)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("enrollment defaultTTL: %w", err)
	}
	out.EnrollmentMaxTTL, err = parseOptionalDuration(config.Auth.Enrollment.MaxTTL)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("enrollment maxTTL: %w", err)
	}
	return out, nil
}

func buildAuthenticatorChain(ctx context.Context, providers []ProviderYAMLConfig) (*controlauth.AuthenticatorChain, error) {
	authenticators := make([]controlauth.RequestAuthenticator, 0, len(providers))
	for _, provider := range providers {
		name := strings.TrimSpace(provider.Name)
		providerType := strings.ToLower(strings.TrimSpace(provider.Type))
		switch providerType {
		case "":
			return nil, fmt.Errorf("provider %q has empty type", name)
		case "apikey", "api-key":
			keys := make([]controlauth.APIKey, 0, len(provider.Keys))
			for _, key := range provider.Keys {
				keys = append(keys, controlauth.APIKey{
					ID:     key.ID,
					Hash:   key.Hash,
					Value:  key.Value,
					Env:    key.Env,
					File:   key.File,
					Groups: key.Groups,
					Roles:  key.Roles,
				})
			}
			authenticator, err := controlauth.NewAPIKeyAuthenticator(name, keys)
			if err != nil {
				return nil, err
			}
			authenticators = append(authenticators, authenticator)
		case "oidc":
			authenticator, err := controlauth.NewOIDCAuthenticator(ctx, controlauth.OIDCConfig{
				Issuer:         provider.Issuer,
				Audience:       provider.Audience,
				JWKSURL:        provider.JWKSURL,
				GroupsClaim:    provider.GroupsClaim,
				RolesClaim:     provider.RolesClaim,
				RequiredClaims: provider.RequiredClaims,
			})
			if err != nil {
				return nil, err
			}
			authenticators = append(authenticators, controlauth.NewOIDCRequestAuthenticator(name, authenticator))
		case "spiffe":
			authenticators = append(authenticators, controlauth.NewSPIFFERequestAuthenticator(name))
		default:
			return nil, fmt.Errorf("provider %q has unsupported type %q", name, provider.Type)
		}
	}
	return controlauth.NewAuthenticatorChain(authenticators), nil
}

func hasRBACConfig(config RBACYAMLConfig) bool {
	return len(config.RoleBindings) > 0 || len(config.Roles) > 0
}

func buildRBACAuthorizer(config RBACYAMLConfig) (*controlauth.RBACAuthorizer, error) {
	roleBindings := map[string][]string{}
	for _, binding := range config.RoleBindings {
		subject := strings.TrimSpace(binding.Subject)
		if subject == "" {
			return nil, fmt.Errorf("role binding subject is required")
		}
		for _, role := range binding.Roles {
			role = strings.TrimSpace(role)
			if role != "" {
				roleBindings[subject] = append(roleBindings[subject], role)
			}
		}
		if len(roleBindings[subject]) == 0 {
			return nil, fmt.Errorf("role binding %q requires at least one role", subject)
		}
	}
	roles := map[string][]controlauth.AdminPermission{}
	for name, role := range config.Roles {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("role name is required")
		}
		for _, permission := range role.Permissions {
			permission = strings.TrimSpace(permission)
			if permission != "" {
				roles[name] = append(roles[name], controlauth.AdminPermission(permission))
			}
		}
		if len(roles[name]) == 0 {
			return nil, fmt.Errorf("role %q requires at least one permission", name)
		}
	}
	return controlauth.NewRBACAuthorizer(controlauth.RBACConfig{RoleBindings: roleBindings, Roles: roles}), nil
}

func buildEnrollmentAuthorizer(grants []EnrollmentGrantYAML) (*controlenrollment.Authorizer, error) {
	config := make([]controlenrollment.GrantConfig, 0, len(grants))
	for _, grant := range grants {
		workloads := make([]controlenrollment.WorkloadSelector, 0, len(grant.Workloads))
		for _, workload := range grant.Workloads {
			workloads = append(workloads, controlenrollment.WorkloadSelector{
				Namespace: workload.Namespace,
				Name:      workload.Name,
			})
		}
		config = append(config, controlenrollment.GrantConfig{
			Subject:     grant.Subject,
			Subjects:    grant.Subjects,
			Permissions: grant.Permissions,
			Workloads:   workloads,
		})
	}
	return controlenrollment.NewAuthorizerFromConfig(config)
}

func parseOptionalDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	return time.ParseDuration(value)
}
