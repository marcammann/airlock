package controlplane

import "strings"

type AdminPermission string

const (
	AdminPermissionPolicyRead AdminPermission = "policy:read"
	AdminPermissionProxyRead  AdminPermission = "proxy:read"
	AdminPermissionAuditRead  AdminPermission = "audit:read"
)

type AdminPrincipal struct {
	Subject string
	Email   string
	Groups  []string
	Roles   []string
}

type RBACConfig struct {
	RoleBindings map[string][]string
}

type RBACAuthorizer struct {
	roleBindings map[string][]string
}

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
	return &RBACAuthorizer{roleBindings: bindings}
}

func (a *RBACAuthorizer) Authorize(principal AdminPrincipal, permission AdminPermission) bool {
	if a == nil {
		return true
	}
	for _, role := range a.rolesFor(principal) {
		if roleAllows(role, permission) {
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
	}
	if principal.Email != "" {
		for _, role := range a.roleBindings["user:"+principal.Email] {
			add(role)
		}
	}
	if principal.Subject != "" {
		for _, role := range a.roleBindings["sub:"+principal.Subject] {
			add(role)
		}
	}

	return roles
}

func roleAllows(role string, permission AdminPermission) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "owner", "admin":
		return true
	case "operator", "viewer", "auditor":
		return permission == AdminPermissionPolicyRead || permission == AdminPermissionProxyRead || permission == AdminPermissionAuditRead
	default:
		return false
	}
}
