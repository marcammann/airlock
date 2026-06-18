package enrollment

import (
	"fmt"
	"strings"

	controlauth "github.com/marcammann/airlock/internal/controlplane/auth"
)

// Authorizer checks whether a principal may create workload enrollment tokens.
type Authorizer struct {
	grants []Grant
}

// Grant allows selected principals to enroll selected workloads.
type Grant struct {
	Subjects    []string
	Permissions []controlauth.AdminPermission
	Workloads   []WorkloadSelector
}

// WorkloadSelector matches a workload namespace/name pair.
type WorkloadSelector struct {
	Namespace string
	Name      string
}

// NewAuthorizer creates an authorizer from normalized grants.
func NewAuthorizer(grants []Grant) *Authorizer {
	if len(grants) == 0 {
		return nil
	}
	return &Authorizer{grants: append([]Grant(nil), grants...)}
}

// GrantConfig is the string-based config form of an enrollment grant.
type GrantConfig struct {
	Subject     string
	Subjects    []string
	Permissions []string
	Workloads   []WorkloadSelector
}

// NewAuthorizerFromConfig validates config grants and creates an authorizer.
func NewAuthorizerFromConfig(grants []GrantConfig) (*Authorizer, error) {
	out := make([]Grant, 0, len(grants))
	for _, grant := range grants {
		subjects := append([]string(nil), grant.Subjects...)
		if strings.TrimSpace(grant.Subject) != "" {
			subjects = append(subjects, grant.Subject)
		}
		compactSubjects := make([]string, 0, len(subjects))
		for _, subject := range subjects {
			subject = strings.TrimSpace(subject)
			if subject != "" {
				compactSubjects = append(compactSubjects, subject)
			}
		}
		if len(compactSubjects) == 0 {
			return nil, fmt.Errorf("grant requires at least one subject")
		}
		permissions := make([]controlauth.AdminPermission, 0, len(grant.Permissions))
		for _, permission := range grant.Permissions {
			permission = strings.TrimSpace(permission)
			if permission != "" {
				permissions = append(permissions, controlauth.AdminPermission(permission))
			}
		}
		if len(permissions) == 0 {
			return nil, fmt.Errorf("grant for %q requires at least one permission", compactSubjects[0])
		}
		workloads := make([]WorkloadSelector, 0, len(grant.Workloads))
		for _, workload := range grant.Workloads {
			namespace := strings.TrimSpace(workload.Namespace)
			name := strings.TrimSpace(workload.Name)
			if namespace == "" || name == "" {
				return nil, fmt.Errorf("grant workload selectors require namespace and name")
			}
			workloads = append(workloads, WorkloadSelector{Namespace: namespace, Name: name})
		}
		if len(workloads) == 0 {
			return nil, fmt.Errorf("grant for %q requires at least one workload selector", compactSubjects[0])
		}
		out = append(out, Grant{
			Subjects:    compactSubjects,
			Permissions: permissions,
			Workloads:   workloads,
		})
	}
	return NewAuthorizer(out), nil
}

// Authorize reports whether principal may perform permission for a workload.
func (a *Authorizer) Authorize(principal controlauth.AdminPrincipal, permission controlauth.AdminPermission, namespace string, name string) bool {
	if a == nil {
		return false
	}
	subjects := principalSubjectSet(principal)
	for _, grant := range a.grants {
		if !grantAllowsPermission(grant, permission) {
			continue
		}
		if !grantMatchesPrincipal(grant, subjects) {
			continue
		}
		if grantMatchesWorkload(grant, namespace, name) {
			return true
		}
	}
	return false
}

func grantAllowsPermission(grant Grant, permission controlauth.AdminPermission) bool {
	for _, candidate := range grant.Permissions {
		if candidate == controlauth.AdminPermission("*") || candidate == permission {
			return true
		}
	}
	return false
}

func grantMatchesPrincipal(grant Grant, subjects map[string]struct{}) bool {
	for _, subject := range grant.Subjects {
		if _, ok := subjects[subject]; ok {
			return true
		}
	}
	return false
}

func grantMatchesWorkload(grant Grant, namespace string, name string) bool {
	for _, selector := range grant.Workloads {
		namespaceMatches := selector.Namespace == "*" || selector.Namespace == namespace
		nameMatches := selector.Name == "*" || selector.Name == name
		if namespaceMatches && nameMatches {
			return true
		}
	}
	return false
}

func principalSubjectSet(principal controlauth.AdminPrincipal) map[string]struct{} {
	out := map[string]struct{}{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			out[value] = struct{}{}
		}
	}
	add(principal.Subject)
	if principal.Subject != "" {
		add("sub:" + principal.Subject)
	}
	if principal.Email != "" {
		add("user:" + principal.Email)
	}
	if principal.Provider != "" && principal.Subject != "" {
		add("provider:" + principal.Provider + ":sub:" + principal.Subject)
	}
	for _, group := range principal.Groups {
		add(group)
		add("group:" + group)
	}
	return out
}
