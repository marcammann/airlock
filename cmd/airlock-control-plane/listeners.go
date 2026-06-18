package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"

	"github.com/marcammann/airlock/internal/controlplane"
	airlockotel "github.com/marcammann/airlock/internal/otel"
	"github.com/marcammann/airlock/internal/telemetry"
)

type controlPlaneListenerOptions struct {
	Config     controlPlaneConfig
	WorkerMode controlplane.AuthMode
	AdminMode  controlplane.AuthMode
	Store      *controlplane.PolicyStore
	Server     *controlplane.Server
}

func buildControlPlaneListeners(ctx context.Context, opts controlPlaneListenerOptions) ([]namedHTTPServer, []func(), error) {
	config := opts.Config
	server := opts.Server
	if server == nil {
		return nil, nil, fmt.Errorf("control-plane server is required")
	}
	if opts.Store == nil {
		return nil, nil, fmt.Errorf("policy store is required")
	}

	var servers []namedHTTPServer
	var cleanup []func()
	if config.HealthListen != "" {
		healthServer := newHTTPServer(config.HealthListen, telemetry.ControlPlaneHTTPMetricsHandler("health", airlockotel.HTTPHandler("airlock.health", server.HealthHandler())))
		servers = append(servers, namedHTTPServer{
			Name:   "health",
			Addr:   config.HealthListen,
			Server: healthServer,
			Serve:  healthServer.ListenAndServe,
		})
	}
	if config.MetricsListen != "" {
		metricsServer := newHTTPServer(config.MetricsListen, telemetry.MetricsHandler())
		servers = append(servers, namedHTTPServer{
			Name:   "metrics",
			Addr:   config.MetricsListen,
			Server: metricsServer,
			Serve:  metricsServer.ListenAndServe,
		})
	}
	if config.AdminListen != "" {
		adminServer := newHTTPServer(config.AdminListen, telemetry.ControlPlaneHTTPMetricsHandler("admin", airlockotel.HTTPHandler("airlock.admin", server.AdminHandler())))
		name := fmt.Sprintf("admin API admin_auth=%s auth_config=%t", opts.AdminMode, strings.TrimSpace(config.AuthConfigPath) != "")
		if config.AdminTLSCertFile != "" && config.AdminTLSKeyFile != "" {
			adminServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			servers = append(servers, namedHTTPServer{
				Name:   name,
				Addr:   config.AdminListen,
				Server: adminServer,
				Serve:  func() error { return adminServer.ListenAndServeTLS(config.AdminTLSCertFile, config.AdminTLSKeyFile) },
			})
		} else {
			servers = append(servers, namedHTTPServer{
				Name:   name,
				Addr:   config.AdminListen,
				Server: adminServer,
				Serve:  adminServer.ListenAndServe,
			})
		}
	}

	switch opts.WorkerMode {
	case controlplane.AuthModeNone:
		slog.Info("airlock-control-plane worker API configured", "listen", config.Listen, "policyMappings", opts.Store.Len(), "workerAuth", opts.WorkerMode, "adminAuth", opts.AdminMode)
		workerServer := newHTTPServer(config.Listen, telemetry.ControlPlaneHTTPMetricsHandler("worker", airlockotel.HTTPHandler("airlock.worker", server.WorkerHandler())))
		servers = append(servers, namedHTTPServer{
			Name:   fmt.Sprintf("worker API worker_auth=%s admin_auth=%s", opts.WorkerMode, opts.AdminMode),
			Addr:   config.Listen,
			Server: workerServer,
			Serve:  workerServer.ListenAndServe,
		})
	case controlplane.AuthModeSPIFFE:
		workerServer, closeSource, err := newSPIFFEServer(ctx, config.Listen, config.SPIFFESocket, config.SPIFFETrustDomain, server)
		if err != nil {
			return nil, nil, err
		}
		cleanup = append(cleanup, closeSource)
		servers = append(servers, namedHTTPServer{
			Name:   fmt.Sprintf("worker API SPIFFE mTLS trust_domain=%s", config.SPIFFETrustDomain),
			Addr:   config.Listen,
			Server: workerServer,
			Serve:  func() error { return workerServer.ListenAndServeTLS("", "") },
		})
	default:
		return nil, nil, fmt.Errorf("unsupported worker auth mode %q", config.WorkerAuth)
	}
	return servers, cleanup, nil
}
