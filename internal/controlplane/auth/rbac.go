package auth

import "strings"

// AdminPermission names an operation that can be granted through admin RBAC.
type AdminPermission string

const (
	// AdminPermissionPolicyRead allows reading policies.
	AdminPermissionPolicyRead AdminPermission = "policy:read"
	// AdminPermissionWorkloadRead allows reading workloads.
	AdminPermissionWorkloadRead AdminPermission = "workload:read"
	// AdminPermissionProxyRead allows reading proxy instances.
	AdminPermissionProxyRead AdminPermission = "proxy:read"
	// AdminPermissionAuditRead allows reading audit and event data.
	AdminPermissionAuditRead AdminPermission = "audit:read"
	// AdminPermissionEnrollmentCreate allows creating workload enrollment tokens.
	AdminPermissionEnrollmentCreate AdminPermission = "enrollment:create"
)

// AdminPrincipal is the authenticated admin identity used for RBAC decisions.
type AdminPrincipal struct {
	Provider string
	Subject  string
	Email    string
	Groups   []string
	Roles    []string
}

// RBACConfig configures admin role bindings and custom role permissions.
type RBACConfig struct {
	RoleBindings map[string][]string
	Roles        map[string][]AdminPermission
}

// RBACAuthorizer evaluates admin permissions for authenticated principals.
type RBACAuthorizer struct {
	roleBindings map[string][]string
	roles        map[string]map[AdminPermission]struct{}
}

// NewRBACAuthorizer builds an authorizer from RBAC configuration.
func NewRBACAuthorizer(config RBACConfig) *RBACAuthorizer {
	bindings := make(map[string][]string, len(config.RoleBindings))
	for key, roles := range config.RoleBindings {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		for _, role := range roles {
			role = strings.TrimSpace(role)
			if role != "" {
				bindings[key] = append(bindings[key], role)
			}
		}
	}
	customRoles := map[string]map[AdminPermission]struct{}{}
	for role, permissions := range config.Roles {
		role = strings.ToLower(strings.TrimSpace(role))
		if role == "" {
			continue
		}
		customRoles[role] = map[AdminPermission]struct{}{}
		for _, permission := range permissions {
			permission = AdminPermission(strings.TrimSpace(string(permission)))
			if permission != "" {
				customRoles[role][permission] = struct{}{}
			}
		}
	}
	return &RBACAuthorizer{roleBindings: bindings, roles: customRoles}
}

// Authorize reports whether the principal has the requested permission.
func (a *RBACAuthorizer) Authorize(principal AdminPrincipal, permission AdminPermission) bool {
	if a == nil {
		return true
	}
	for _, role := range a.rolesFor(principal) {
		if a.roleAllows(role, permission) {
			return true
		}
	}
	return false
}

func (a *RBACAuthorizer) rolesFor(principal AdminPrincipal) []string {
	seen := map[string]struct{}{}
	var roles []string
	add := func(role string) {
		role = strings.ToLower(strings.TrimSpace(role))
		if role == "" {
			return
		}
		if _, ok := seen[role]; ok {
			return
		}
		seen[role] = struct{}{}
		roles = append(roles, role)
	}

	for _, role := range principal.Roles {
		add(role)
	}
	for _, group := range principal.Groups {
		for _, role := range a.roleBindings[group] {
			add(role)
		}
		for _, role := range a.roleBindings["group:"+group] {
			add(role)
		}
	}
	if principal.Email != "" {
		for _, role := range a.roleBindings["user:"+principal.Email] {
			add(role)
		}
	}
	if principal.Subject != "" {
		for _, role := range a.roleBindings[principal.Subject] {
			add(role)
		}
		for _, role := range a.roleBindings["sub:"+principal.Subject] {
			add(role)
		}
	}
	if principal.Provider != "" && principal.Subject != "" {
		for _, role := range a.roleBindings["provider:"+principal.Provider+":sub:"+principal.Subject] {
			add(role)
		}
	}

	return roles
}

func (a *RBACAuthorizer) roleAllows(role string, permission AdminPermission) bool {
	if permissions, ok := a.roles[strings.ToLower(strings.TrimSpace(role))]; ok {
		if _, ok := permissions[AdminPermission("*")]; ok {
			return true
		}
		_, ok := permissions[permission]
		return ok
	}

	switch strings.ToLower(strings.TrimSpace(role)) {
	case "owner", "admin":
		return true
	case "operator":
		return permission == AdminPermissionPolicyRead ||
			permission == AdminPermissionWorkloadRead ||
			permission == AdminPermissionProxyRead ||
			permission == AdminPermissionAuditRead ||
			permission == AdminPermissionEnrollmentCreate
	case "viewer":
		return permission == AdminPermissionPolicyRead ||
			permission == AdminPermissionWorkloadRead ||
			permission == AdminPermissionProxyRead
	case "auditor":
		return permission == AdminPermissionPolicyRead ||
			permission == AdminPermissionWorkloadRead ||
			permission == AdminPermissionProxyRead ||
			permission == AdminPermissionAuditRead
	default:
		return false
	}
}
