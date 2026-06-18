package controlplane

import controlauth "github.com/marcammann/airlock/internal/controlplane/auth"

// AdminPermission is one admin API permission.
type AdminPermission = controlauth.AdminPermission

const (
	// AdminPermissionPolicyRead permits reading policies.
	AdminPermissionPolicyRead = controlauth.AdminPermissionPolicyRead
	// AdminPermissionWorkloadRead permits reading workloads.
	AdminPermissionWorkloadRead = controlauth.AdminPermissionWorkloadRead
	// AdminPermissionProxyRead permits reading proxy status.
	AdminPermissionProxyRead = controlauth.AdminPermissionProxyRead
	// AdminPermissionAuditRead permits reading audit/event data.
	AdminPermissionAuditRead = controlauth.AdminPermissionAuditRead
	// AdminPermissionEnrollmentCreate permits creating enrollment tokens.
	AdminPermissionEnrollmentCreate = controlauth.AdminPermissionEnrollmentCreate
)

// AdminPrincipal is the authenticated admin identity.
type AdminPrincipal = controlauth.AdminPrincipal

// RBACConfig configures admin roles and role bindings.
type RBACConfig = controlauth.RBACConfig

// RBACAuthorizer evaluates admin permissions.
type RBACAuthorizer = controlauth.RBACAuthorizer

// NewRBACAuthorizer creates an admin RBAC authorizer.
func NewRBACAuthorizer(config RBACConfig) *RBACAuthorizer {
	return controlauth.NewRBACAuthorizer(config)
}
