package controlplane

import (
	"context"

	authconfig "github.com/marcammann/airlock/internal/controlplane/authconfig"
)

// RuntimeAuthConfig is the runtime auth configuration built from YAML.
type RuntimeAuthConfig = authconfig.RuntimeConfig

// AuthConfigFile is the top-level auth YAML file.
type AuthConfigFile = authconfig.ConfigFile

// AuthYAMLConfig groups admin and enrollment auth settings.
type AuthYAMLConfig = authconfig.YAMLConfig

// AdminAuthYAMLConfig configures admin API auth.
type AdminAuthYAMLConfig = authconfig.AdminYAMLConfig

// EnrollmentAuthYAMLConfig configures enrollment auth.
type EnrollmentAuthYAMLConfig = authconfig.EnrollmentYAMLConfig

// AuthProviderYAMLConfig configures one auth provider.
type AuthProviderYAMLConfig = authconfig.ProviderYAMLConfig

// APIKeyYAML configures one API key.
type APIKeyYAML = authconfig.APIKeyYAML

// RBACYAMLConfig configures role bindings and roles.
type RBACYAMLConfig = authconfig.RBACYAMLConfig

// RoleBindingYAML maps a subject to roles.
type RoleBindingYAML = authconfig.RoleBindingYAML

// RoleYAMLConfig lists permissions for a role.
type RoleYAMLConfig = authconfig.RoleYAMLConfig

// EnrollmentGrantYAML grants enrollment access.
type EnrollmentGrantYAML = authconfig.EnrollmentGrantYAML

// EnrollmentWorkloadYAML selects a workload in an enrollment grant.
type EnrollmentWorkloadYAML = authconfig.EnrollmentWorkloadYAML

// LoadRuntimeAuthConfig reads auth YAML and builds runtime auth components.
func LoadRuntimeAuthConfig(ctx context.Context, path string) (RuntimeAuthConfig, error) {
	return authconfig.LoadRuntimeConfig(ctx, path)
}

// BuildRuntimeAuthConfig builds runtime auth components from parsed config.
func BuildRuntimeAuthConfig(ctx context.Context, config AuthConfigFile) (RuntimeAuthConfig, error) {
	return authconfig.BuildRuntimeConfig(ctx, config)
}
