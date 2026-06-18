package controlplane

import (
	"fmt"
	"strings"

	"github.com/marcammann/airlock/internal/controlplane"
)

func parseRBACBindings(bindings []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, binding := range bindings {
		binding = strings.TrimSpace(binding)
		if binding == "" {
			continue
		}
		subject, roles, ok := strings.Cut(binding, "=")
		if !ok {
			return nil, fmt.Errorf("admin RBAC binding %q must use subject=role[,role]", binding)
		}
		subject = strings.TrimSpace(subject)
		if subject == "" {
			return nil, fmt.Errorf("admin RBAC binding %q has empty subject", binding)
		}
		for _, role := range strings.Split(roles, ",") {
			role = strings.TrimSpace(role)
			if role != "" {
				out[subject] = append(out[subject], role)
			}
		}
		if len(out[subject]) == 0 {
			return nil, fmt.Errorf("admin RBAC binding %q has no roles", binding)
		}
	}
	return out, nil
}

func validateAuthConfig(mode controlplane.AuthMode, name string, insecure bool) error {
	switch mode {
	case controlplane.AuthModeNone:
		if !insecure {
			return fmt.Errorf("%s auth mode none requires --insecure", name)
		}
		return nil
	case controlplane.AuthModeSPIFFE:
		return nil
	case controlplane.AuthModeOIDC:
		if name == "worker" {
			return fmt.Errorf("worker auth mode oidc is not supported")
		}
		return nil
	default:
		return fmt.Errorf("unsupported %s auth mode %q", name, mode)
	}
}

func validateAdminTLSConfig(adminListen string, certFile string, keyFile string, insecure bool) error {
	if strings.TrimSpace(adminListen) == "" {
		return nil
	}
	certFile = strings.TrimSpace(certFile)
	keyFile = strings.TrimSpace(keyFile)
	if (certFile == "") != (keyFile == "") {
		return fmt.Errorf("--admin-tls-cert and --admin-tls-key must be set together")
	}
	if certFile == "" && !insecure {
		return fmt.Errorf("--admin-listen requires --admin-tls-cert and --admin-tls-key unless --insecure is set")
	}
	return nil
}
