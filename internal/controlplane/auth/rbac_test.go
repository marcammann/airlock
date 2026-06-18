package auth

import "testing"

func TestRBACAuthorizerBuiltInRoles(t *testing.T) {
	authorizer := NewRBACAuthorizer(RBACConfig{})
	operator := AdminPrincipal{Roles: []string{"operator"}}
	if !authorizer.Authorize(operator, AdminPermissionEnrollmentCreate) {
		t.Fatal("operator should create enrollments")
	}
	viewer := AdminPrincipal{Roles: []string{"viewer"}}
	if authorizer.Authorize(viewer, AdminPermissionAuditRead) {
		t.Fatal("viewer should not read audit logs")
	}
}

func TestRBACAuthorizerRoleBindings(t *testing.T) {
	authorizer := NewRBACAuthorizer(RBACConfig{
		RoleBindings: map[string][]string{
			"group:platform":          {"auditor"},
			"user:admin@example.test": {"owner"},
		},
	})
	if !authorizer.Authorize(AdminPrincipal{Groups: []string{"platform"}}, AdminPermissionAuditRead) {
		t.Fatal("platform group should inherit auditor")
	}
	if !authorizer.Authorize(AdminPrincipal{Email: "admin@example.test"}, AdminPermissionEnrollmentCreate) {
		t.Fatal("admin user should inherit owner")
	}
}

func TestRBACAuthorizerCustomRole(t *testing.T) {
	authorizer := NewRBACAuthorizer(RBACConfig{
		RoleBindings: map[string][]string{"sub:alice": {"policy-reader"}},
		Roles: map[string][]AdminPermission{
			"policy-reader": {AdminPermissionPolicyRead},
		},
	})
	principal := AdminPrincipal{Subject: "alice"}
	if !authorizer.Authorize(principal, AdminPermissionPolicyRead) {
		t.Fatal("custom role should allow policy read")
	}
	if authorizer.Authorize(principal, AdminPermissionWorkloadRead) {
		t.Fatal("custom role should not allow workload read")
	}
}
