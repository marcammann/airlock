// Package controlplane runs the Airlock control-plane binary.
package controlplane

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/marcammann/airlock/internal/controlplane"
	airlockotel "github.com/marcammann/airlock/internal/otel"
)

// Run starts the control-plane and blocks until a signal is received or an error occurs.
func Run() error {
	env, err := loadControlPlaneEnv()
	if err != nil {
		return err
	}
	config, flagState := parseControlPlaneFlags(env)
	logFormat := config.LogFormat
	otelExporterOTLPEndpoint := config.OTELExporterOTLPEndpoint
	if err := configureLogger(logFormat); err != nil {
		return err
	}
	tracingShutdown, err := airlockotel.ConfigureTracing(context.Background(), "airlock-control-plane", otelExporterOTLPEndpoint)
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tracingShutdown(shutdownCtx); err != nil {
			slog.Error("shutdown OpenTelemetry tracing failed", "error", err)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	policyRuntime, err := buildControlPlanePolicyRuntime(ctx, config)
	if err != nil {
		return err
	}
	store := policyRuntime.Store
	server, workerMode, adminMode, err := buildControlPlaneServer(ctx, config, flagState, store)
	if err != nil {
		return err
	}
	if config.KubeSource {
		if err := (&controlplane.KubernetesReconciler{Options: controlplane.KubernetesReconcileOptions{
			Namespace:      config.KubeNamespace,
			Server:         server,
			SPIREOptions:   policyRuntime.SPIREOptions,
			SPIREReconcile: config.SPIREReconcile,
			VaultOptions: controlplane.VaultReconcileOptions{
				AdminToken: policyRuntime.VaultToken,
				Audit:      os.Stderr,
			},
			VaultReconcile: config.VaultReconcile,
		}}).SetupWithManager(policyRuntime.KubeRuntime.Manager); err != nil {
			return err
		}
		if strings.TrimSpace(config.WebhookListen) != "" {
			controlplane.RegisterInjectionWebhook(policyRuntime.KubeRuntime.Manager.GetWebhookServer(), server, injectionOptionsFromConfig(config))
		}
		go runKubernetesManager(ctx, policyRuntime.KubeRuntime.Manager, stop)
	}
	go server.RunMaintenance(ctx)
	servers, cleanup, err := buildControlPlaneListeners(ctx, controlPlaneListenerOptions{
		Config:     config,
		WorkerMode: workerMode,
		AdminMode:  adminMode,
		Store:      store,
		Server:     server,
	})
	if err != nil {
		return err
	}
	defer func() {
		for _, fn := range cleanup {
			fn()
		}
	}()
	return runHTTPServers(ctx, servers)
}

func configureLogger(format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	case "text":
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	default:
		return fmt.Errorf("--log-format must be json or text")
	}
	return nil
}
