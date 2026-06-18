package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/marcammann/airlock/internal/controlplane"
)

func buildControlPlaneServer(ctx context.Context, config controlPlaneConfig, flagState controlPlaneFlagState, store *controlplane.PolicyStore) (*controlplane.Server, controlplane.AuthMode, controlplane.AuthMode, error) {
	workerMode := controlplane.AuthMode(config.WorkerAuth)
	adminMode := controlplane.AuthMode(config.AdminAuth)
	var runtimeAuth controlplane.RuntimeAuthConfig
	var err error
	if strings.TrimSpace(config.AuthConfigPath) != "" {
		runtimeAuth, err = controlplane.LoadRuntimeAuthConfig(ctx, config.AuthConfigPath)
		if err != nil {
			return nil, "", "", err
		}
		if runtimeAuth.AdminAuthenticator != nil {
			adminMode = controlplane.AuthModeConfig
		}
	}
	if config.Insecure && !flagState.WorkerAuthExplicit {
		workerMode = controlplane.AuthModeNone
	}
	if config.Insecure && !flagState.AdminAuthExplicit && runtimeAuth.AdminAuthenticator == nil {
		adminMode = controlplane.AuthModeNone
	}
	if err := validateAuthConfig(workerMode, "worker", config.Insecure); err != nil {
		return nil, "", "", err
	}
	if config.AdminListen != "" && runtimeAuth.AdminAuthenticator == nil {
		if err := validateAuthConfig(adminMode, "admin", config.Insecure); err != nil {
			return nil, "", "", err
		}
	}
	if err := validateAdminTLSConfig(config.AdminListen, config.AdminTLSCertFile, config.AdminTLSKeyFile, config.Insecure); err != nil {
		return nil, "", "", err
	}
	if config.Insecure {
		slog.Warn("airlock-control-plane insecure mode enabled", "reason", "auth mode none is allowed")
	}

	eventLogMode, err := validateControlPlaneRuntimeConfig(config)
	if err != nil {
		return nil, "", "", err
	}

	var adminOIDC *controlplane.OIDCAuthenticator
	if config.AdminListen != "" && adminMode == controlplane.AuthModeOIDC && runtimeAuth.AdminAuthenticator == nil {
		adminOIDC, err = controlplane.NewOIDCAuthenticator(ctx, controlplane.OIDCConfig{
			Issuer:      config.AdminOIDCIssuer,
			Audience:    config.AdminOIDCAudience,
			JWKSURL:     config.AdminOIDCJWKSURL,
			GroupsClaim: config.AdminOIDCGroupsClaim,
			RolesClaim:  config.AdminOIDCRolesClaim,
		})
		if err != nil {
			return nil, "", "", err
		}
	}
	roleBindings, err := parseRBACBindings(config.AdminRBACBindings)
	if err != nil {
		return nil, "", "", err
	}
	rbac := controlplane.NewRBACAuthorizer(controlplane.RBACConfig{RoleBindings: roleBindings})
	if runtimeAuth.AdminRBAC != nil {
		rbac = runtimeAuth.AdminRBAC
	}

	server := controlplane.NewServerWithOptions(store, controlplane.ServerOptions{
		WorkerAuthMode:           workerMode,
		AdminAuthMode:            adminMode,
		AdminOIDC:                adminOIDC,
		AdminAuthenticator:       runtimeAuth.AdminAuthenticator,
		AdminRBAC:                rbac,
		EnrollmentAuthenticator:  runtimeAuth.EnrollmentAuthenticator,
		EnrollmentAuthorizer:     runtimeAuth.EnrollmentAuthorizer,
		EnrollmentDefaultTTL:     runtimeAuth.EnrollmentDefaultTTL,
		EnrollmentMaxTTL:         runtimeAuth.EnrollmentMaxTTL,
		HeartbeatStaleThreshold:  config.HeartbeatStaleThreshold,
		EventLogMode:             eventLogMode,
		EventLogLimit:            config.EventLogLimit,
		EventLogTTL:              config.EventLogTTL,
		EventIngestRate:          config.EventIngestRate,
		EventIngestBurst:         config.EventIngestBurst,
		EventIngestRatePerProxy:  config.EventIngestRatePerProxy,
		EventIngestBurstPerProxy: config.EventIngestBurstPerProxy,
		Insecure:                 config.Insecure,
		Audit:                    os.Stderr,
	})
	return server, workerMode, adminMode, nil
}

func validateControlPlaneRuntimeConfig(config controlPlaneConfig) (controlplane.EventLogMode, error) {
	if strings.TrimSpace(config.WebhookListen) != "" && !config.KubeSource {
		return "", fmt.Errorf("--webhook-listen requires --kube-source")
	}
	if config.HeartbeatStaleThreshold <= 0 {
		return "", fmt.Errorf("--heartbeat-stale-threshold must be greater than zero")
	}
	eventLogMode := controlplane.EventLogMode(strings.TrimSpace(config.EventLog))
	switch eventLogMode {
	case controlplane.EventLogMemory, controlplane.EventLogDisabled:
	default:
		return "", fmt.Errorf("--event-log must be memory or disabled")
	}
	if config.EventLogLimit <= 0 {
		return "", fmt.Errorf("--event-log-limit must be greater than zero")
	}
	if config.EventLogTTL <= 0 {
		return "", fmt.Errorf("--event-log-ttl must be greater than zero")
	}
	if config.EventIngestRate <= 0 {
		return "", fmt.Errorf("--event-ingest-rate must be greater than zero")
	}
	if config.EventIngestBurst <= 0 {
		return "", fmt.Errorf("--event-ingest-burst must be greater than zero")
	}
	if config.EventIngestRatePerProxy <= 0 {
		return "", fmt.Errorf("--event-ingest-rate-per-proxy must be greater than zero")
	}
	if config.EventIngestBurstPerProxy <= 0 {
		return "", fmt.Errorf("--event-ingest-burst-per-proxy must be greater than zero")
	}
	return eventLogMode, nil
}
