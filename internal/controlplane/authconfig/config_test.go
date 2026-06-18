package authconfig

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildRuntimeConfigBuildsAPIKeyRBACAndEnrollmentGrants(t *testing.T) {
	config := ConfigFile{
		Auth: YAMLConfig{
			Admin: AdminYAMLConfig{
				Providers: []ProviderYAMLConfig{{
					Name: "admin-key",
					Type: "api-key",
					Keys: []APIKeyYAML{{
						ID:     "admin",
						Value:  "admin-token",
						Groups: []string{"platform"},
					}},
				}},
				RBAC: RBACYAMLConfig{
					RoleBindings: []RoleBindingYAML{{Subject: "group:platform", Roles: []string{"admin"}}},
				},
			},
			Enrollment: EnrollmentYAMLConfig{
				Providers: []ProviderYAMLConfig{{
					Name: "dispatcher-key",
					Type: "api-key",
					Keys: []APIKeyYAML{{
						ID:    "dispatcher",
						Value: "dispatcher-token",
						Roles: []string{"dispatcher"},
					}},
				}},
				Grants: []EnrollmentGrantYAML{{
					Subject:     "provider:dispatcher-key:sub:key:dispatcher",
					Permissions: []string{"enrollment:create"},
					Workloads:   []EnrollmentWorkloadYAML{{Namespace: "demo", Name: "code-agent"}},
				}},
				DefaultTTL: "1m",
				MaxTTL:     "5m",
			},
		},
	}

	runtimeConfig, err := BuildRuntimeConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	adminRequest := httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil)
	adminRequest.Header.Set("Authorization", "Bearer admin-token")
	adminPrincipal, err := runtimeConfig.AdminAuthenticator.AuthenticateRequest(context.Background(), adminRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !runtimeConfig.AdminRBAC.Authorize(adminPrincipal, "workload:read") {
		t.Fatal("admin principal was not authorized for workload:read")
	}

	enrollmentRequest := httptest.NewRequest(http.MethodPost, "/v1/enrollments", nil)
	enrollmentRequest.Header.Set("Authorization", "Bearer dispatcher-token")
	dispatcherPrincipal, err := runtimeConfig.EnrollmentAuthenticator.AuthenticateRequest(context.Background(), enrollmentRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !runtimeConfig.EnrollmentAuthorizer.Authorize(dispatcherPrincipal, "enrollment:create", "demo", "code-agent") {
		t.Fatal("dispatcher principal was not authorized to create enrollment for demo/code-agent")
	}
	if runtimeConfig.EnrollmentAuthorizer.Authorize(dispatcherPrincipal, "enrollment:create", "prod", "code-agent") {
		t.Fatal("dispatcher principal was authorized for an unexpected workload")
	}
}
