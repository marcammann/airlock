// Package proxyworker runs the Airlock proxy-worker binary.
package proxyworker

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	airlockotel "github.com/marcammann/airlock/internal/otel"
	"github.com/marcammann/airlock/internal/proxyworker/builtin"
	workerenvoy "github.com/marcammann/airlock/internal/proxyworker/envoy"
	workertel "github.com/marcammann/airlock/internal/proxyworker/telemetry"
	"github.com/marcammann/airlock/internal/telemetry"
)

// Run starts the proxy-worker and blocks until a signal is received or an error occurs.
func Run() error {
	env, err := loadProxyWorkerEnv()
	if err != nil {
		return err
	}
	config, err := parseProxyWorkerFlags(env)
	if err != nil {
		return err
	}
	if err := configureLogger(config.LogFormat); err != nil {
		return err
	}
	tracingShutdown, err := airlockotel.ConfigureTracing(context.Background(), "airlock-proxy-worker", config.OTELExporterOTLPEndpoint)
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
	if strings.TrimSpace(config.MetricsListen) != "" {
		startMetricsServer(ctx, strings.TrimSpace(config.MetricsListen))
	}
	initialPolicy, err := loadInitialPolicy(ctx, initialPolicyOptions{
		NoControlPlane:           config.NoControlPlane,
		PolicyPath:               config.PolicyPath,
		ControlPlaneURL:          config.ControlPlaneURL,
		ControlPlaneAuth:         config.ControlPlaneAuth,
		ControlPlaneAuthExplicit: config.ControlPlaneAuthExplicit,
		Insecure:                 config.Insecure,
		WorkloadIdentity:         config.WorkloadIdentity,
		EnrollmentToken:          config.EnrollmentToken,
		EnrollmentTokenFile:      config.EnrollmentTokenFile,
		ControlPlaneServerID:     config.ControlPlaneServerID,
		SPIFFESocket:             config.SPIFFESocket,
	})
	if err != nil {
		return err
	}
	defer func() {
		if initialPolicy.ClientCloser != nil {
			_ = initialPolicy.ClientCloser.Close()
		}
	}()
	policy := initialPolicy.Policy
	policyFetchedAt := initialPolicy.FetchedAt
	policyETag := initialPolicy.ETag
	controlPlaneClient := initialPolicy.Client
	controlPlaneProvider := initialPolicy.Provider

	reloadableSecrets, err := buildReloadableSecrets(ctx, policy, config.SPIFFESocket, config.SecretFileRoot)
	if err != nil {
		return err
	}
	tlsAssets, err := loadProxyTLSAssets(config.MITMCACert, config.MITMCAKey, config.UpstreamCACert)
	if err != nil {
		return err
	}

	log := workertel.NewStderrEventLog()
	reporters, err := startReporters(ctx, reporterSetupOptions{
		NoControlPlane:           config.NoControlPlane,
		EventReport:              config.EventReport,
		EventEndpoint:            config.EventEndpoint,
		ControlPlaneURL:          config.ControlPlaneURL,
		Proxy:                    config.Proxy,
		Policy:                   policy,
		Insecure:                 config.Insecure,
		ControlPlaneAuth:         config.ControlPlaneAuth,
		ControlPlaneClient:       controlPlaneClient,
		HeartbeatInterval:        config.HeartbeatInterval,
		PolicyFetchedAt:          policyFetchedAt,
		EventReportRate:          config.EventReportRate,
		EventReportBurst:         config.EventReportBurst,
		EventReportPendingLimit:  config.EventReportPendingLimit,
		EventReportFlushInterval: config.EventReportFlushInterval,
		Log:                      log,
		ProcessStartedAt:         time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	log.Record(workertel.DecisionNone, fmt.Sprintf(
		"airlock-proxy-worker loaded policy=%s policy_version=%s workload=%s proxy=%s:%s control_plane=%t https_intercept=%t",
		policy.PolicyName,
		policy.Version,
		policy.Workload.SPIFFEID,
		config.Proxy.Protocol,
		config.Proxy.Mode,
		!config.NoControlPlane,
		tlsAssets.MITMCA != nil,
	))
	listener, err := net.Listen("tcp", config.Proxy.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	if config.Proxy.Mode == "envoy" {
		envoyServer, err := workerenvoy.NewServer(policy, reloadableSecrets, log, tlsAssets.MITMCA)
		if err != nil {
			return err
		}
		startPolicyPoller(ctx, config.NoControlPlane, config.ControlPlaneAuth, config.Insecure, config.PolicyPollInterval, controlPlaneProvider, controlPlaneClient, policyETag, config.SPIFFESocket, config.SecretFileRoot, reloadableSecrets, envoyServer, reporters.EventReporter, reporters.HeartbeatReporter, log)
		log.Record(workertel.DecisionNone, fmt.Sprintf("airlock-proxy-worker envoy mode listening on %s", config.Proxy.Listen))
		return envoyServer.Serve(ctx, listener)
	}
	proxy := builtin.NewProxyServerWithOptions(
		policy,
		reloadableSecrets,
		log,
		builtin.ProxyServerOptions{MITMCA: tlsAssets.MITMCA, UpstreamTLSConfig: tlsAssets.UpstreamTLSConfig, MaxResponseBytes: config.MaxResponseBytes},
	)
	startPolicyPoller(ctx, config.NoControlPlane, config.ControlPlaneAuth, config.Insecure, config.PolicyPollInterval, controlPlaneProvider, controlPlaneClient, policyETag, config.SPIFFESocket, config.SecretFileRoot, reloadableSecrets, proxy, reporters.EventReporter, reporters.HeartbeatReporter, log)
	log.Record(workertel.DecisionNone, fmt.Sprintf("airlock-proxy-worker builtin proxy listening on %s", config.Proxy.Listen))
	return proxy.Serve(ctx, listener)
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

func startMetricsServer(ctx context.Context, listen string) {
	server := &http.Server{
		Addr:              listen,
		Handler:           telemetry.MetricsHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		slog.Info("airlock-proxy-worker metrics listener starting", "addr", listen)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("airlock-proxy-worker metrics listener failed", "error", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("airlock-proxy-worker metrics listener shutdown failed", "error", err)
		}
	}()
}
