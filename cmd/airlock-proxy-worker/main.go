package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	worker "github.com/marcammann/airlock/internal/proxyworker"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "airlock-proxy-worker: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		proxies                  proxyFlags
		noControlPlane           = flag.Bool("no-control-plane", false, "load compiled policy from --policy instead of the control plane")
		policyPath               = flag.String("policy", "", "local compiled policy YAML or JSON path")
		mitmCACert               = flag.String("mitm-ca-cert", "", "public CA certificate used for HTTPS interception")
		mitmCAKey                = flag.String("mitm-ca-key", "", "private CA key used for HTTPS interception")
		upstreamCACert           = flag.String("upstream-ca-cert", "", "optional CA certificate bundle used to verify upstream TLS in builtin mode")
		controlPlaneURL          = flag.String("control-plane-url", "", "control-plane policy API URL")
		controlPlaneAuth         = flag.String("control-plane-auth", "spiffe", "control-plane auth mode: spiffe, dev-token, or none")
		workloadIdentity         = flag.String("workload-identity", "", "workload SPIFFE ID")
		devToken                 = flag.String("dev-token", "", "development bearer token for control-plane policy fetch")
		controlPlaneServerID     = flag.String("control-plane-server-id", "", "reserved for SPIFFE control-plane auth")
		spiffeSocket             = flag.String("spiffe-socket", "", "reserved SPIFFE workload API socket URI")
		heartbeatInterval        = flag.Duration("heartbeat-interval", 10*time.Second, "interval for proxy heartbeat reports; set 0 to disable")
		eventReport              = flag.String("event-report", "control-plane", "Airlock event reporting mode: control-plane or disabled")
		eventEndpoint            = flag.String("event-endpoint", "", "Airlock event ingest URL; defaults to the control plane /v1/events endpoint")
		eventReportRate          = flag.Float64("event-report-rate", 1, "maximum Airlock event reports sent per second")
		eventReportBurst         = flag.Int("event-report-burst", 20, "burst of Airlock event reports sent by the proxy")
		eventReportPendingLimit  = flag.Int("event-report-pending-limit", 256, "maximum unique Airlock events aggregated before local suppression")
		eventReportFlushInterval = flag.Duration("event-report-flush-interval", time.Second, "interval for flushing aggregated Airlock events")
		insecureDevMode          = flag.Bool("insecure-dev-mode", false, "allow insecure development control-plane auth modes such as none and dev-token")
	)
	flag.Var(&proxies, "proxy", "proxy listener in protocol:mode[@listen] form, for example http:builtin@127.0.0.1:18080")
	flag.Parse()

	proxyConfig, err := resolveProxyConfig(proxies)
	if err != nil {
		return err
	}
	if proxyConfig.Protocol != "http" || (proxyConfig.Mode != "builtin" && proxyConfig.Mode != "envoy") {
		return fmt.Errorf("Go worker currently supports --proxy http:builtin and --proxy http:envoy; %s:%s is the next parity slice", proxyConfig.Protocol, proxyConfig.Mode)
	}
	if proxyConfig.Mode == "envoy" && *upstreamCACert != "" {
		return fmt.Errorf("--upstream-ca-cert is for http:builtin; configure Envoy upstream TLS trust in the Envoy bootstrap")
	}

	var policy worker.CompiledPolicy
	var policyFetchedAt *time.Time
	ctx := context.Background()
	if *noControlPlane {
		if *policyPath == "" {
			return fmt.Errorf("--no-control-plane requires --policy")
		}
		if *controlPlaneURL != "" {
			return fmt.Errorf("--no-control-plane cannot use --control-plane-url")
		}
		policy, err = worker.NewLocalPolicyProvider(*policyPath).Load()
	} else {
		if *policyPath != "" {
			return fmt.Errorf("control-plane mode uses control-plane policy; remove --policy or add --no-control-plane")
		}
		if *controlPlaneURL == "" || *workloadIdentity == "" {
			return fmt.Errorf("control-plane mode requires --control-plane-url and --workload-identity")
		}
		if err := validateControlPlaneAuth(*controlPlaneAuth, *devToken, *insecureDevMode); err != nil {
			return err
		}
		provider := worker.NewControlPlanePolicyProvider(*controlPlaneURL, *workloadIdentity, "")
		switch *controlPlaneAuth {
		case "spiffe":
			if *controlPlaneServerID == "" {
				return fmt.Errorf("--control-plane-auth spiffe requires --control-plane-server-id")
			}
			policy, err = provider.LoadSPIFFEMTLS(ctx, *controlPlaneServerID, *spiffeSocket)
		case "dev-token":
			provider = worker.NewControlPlanePolicyProvider(*controlPlaneURL, *workloadIdentity, *devToken)
			policy, err = provider.Load()
		case "none":
			policy, err = provider.Load()
		default:
			return fmt.Errorf("unsupported control-plane auth %q; use spiffe, dev-token, or none", *controlPlaneAuth)
		}
	}
	if err != nil {
		return err
	}
	if !*noControlPlane {
		now := time.Now().UTC()
		policyFetchedAt = &now
	}

	secrets, err := worker.NewSecretProviderForPolicy(ctx, policy, *spiffeSocket)
	if err != nil {
		return err
	}

	var mitmCA *worker.CertificateAuthority
	var upstreamTLSConfig *tls.Config
	if *mitmCACert != "" || *mitmCAKey != "" {
		if *mitmCACert == "" || *mitmCAKey == "" {
			return fmt.Errorf("--mitm-ca-cert and --mitm-ca-key must be set together")
		}
		mitmCA, err = worker.LoadCertificateAuthority(*mitmCACert, *mitmCAKey)
		if err != nil {
			return err
		}
	}
	if *upstreamCACert != "" {
		upstreamTLSConfig, err = worker.LoadTLSClientConfigWithRootCAs(*upstreamCACert)
		if err != nil {
			return err
		}
	}

	log := worker.NewStderrEventLog()
	resolvedProxyID := ""
	eventReportMode := strings.TrimSpace(*eventReport)
	if eventReportMode == "" {
		eventReportMode = "control-plane"
	}
	if *noControlPlane && eventReportMode == "control-plane" {
		eventReportMode = "disabled"
	}
	if !*noControlPlane || eventReportMode != "disabled" {
		resolvedProxyID, err = proxyIPID()
		if err != nil {
			return err
		}
	}
	log.Record(fmt.Sprintf(
		"airlock-proxy-worker loaded policy=%s policy_version=%s workload=%s proxy=%s:%s control_plane=%t https_intercept=%t",
		policy.PolicyName,
		policy.Version,
		policy.Workload.SPIFFEID,
		proxyConfig.Protocol,
		proxyConfig.Mode,
		!*noControlPlane,
		mitmCA != nil,
	))
	switch eventReportMode {
	case "disabled":
	case "control-plane":
		if *noControlPlane {
			return fmt.Errorf("--event-report control-plane requires control-plane mode")
		}
		resolvedEventEndpoint := strings.TrimSpace(*eventEndpoint)
		if resolvedEventEndpoint == "" {
			resolvedEventEndpoint = strings.TrimRight(*controlPlaneURL, "/") + "/v1/events"
		}
		eventOpts := worker.EventReporterOptions{
			Endpoint:           resolvedEventEndpoint,
			DevToken:           *devToken,
			ProxyID:            resolvedProxyID,
			ProxyType:          proxyConfig.Protocol + ":" + proxyConfig.Mode,
			WorkloadIdentity:   policy.Workload.SPIFFEID,
			WorkloadName:       policy.PolicyName,
			WorkloadNamespace:  policy.Workload.Namespace,
			EffectiveVersion:   policy.Version,
			SourcePolicyByRule: sourcePolicyByRule(policy),
			RatePerSecond:      *eventReportRate,
			Burst:              *eventReportBurst,
			MaxPendingKeys:     *eventReportPendingLimit,
			FlushInterval:      *eventReportFlushInterval,
		}
		if *controlPlaneAuth == "spiffe" {
			client, closer, err := worker.NewSPIFFEMTLSHTTPClient(ctx, *controlPlaneServerID, *spiffeSocket, 5*time.Second)
			if err != nil {
				return err
			}
			defer closer.Close()
			eventOpts.Client = client
		}
		reporter, err := worker.NewEventReporter(eventOpts)
		if err != nil {
			return err
		}
		log.SetDecisionSink(reporter)
		go reporter.Run(ctx)
	default:
		return fmt.Errorf("--event-report must be control-plane or disabled")
	}
	if !*noControlPlane && *heartbeatInterval > 0 {
		heartbeatOpts := worker.HeartbeatReporterOptions{
			BaseURL:           *controlPlaneURL,
			DevToken:          *devToken,
			ProxyID:           resolvedProxyID,
			ProxyType:         proxyConfig.Protocol + ":" + proxyConfig.Mode,
			WorkloadIdentity:  policy.Workload.SPIFFEID,
			WorkloadName:      policy.PolicyName,
			EffectiveVersion:  policy.Version,
			PolicyFetchedAt:   policyFetchedAt,
			HeartbeatInterval: *heartbeatInterval,
			ProcessStartedAt:  time.Now().UTC(),
			Log:               log,
		}
		if *controlPlaneAuth == "spiffe" {
			client, closer, err := worker.NewSPIFFEMTLSHTTPClient(ctx, *controlPlaneServerID, *spiffeSocket, 5*time.Second)
			if err != nil {
				return err
			}
			defer closer.Close()
			heartbeatOpts.Client = client
		}
		reporter, err := worker.NewHeartbeatReporter(heartbeatOpts)
		if err != nil {
			return err
		}
		go reporter.Run(ctx)
	}
	listener, err := net.Listen("tcp", proxyConfig.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	if proxyConfig.Mode == "envoy" {
		log.Record(fmt.Sprintf("airlock-proxy-worker envoy mode listening on %s", proxyConfig.Listen))
		return worker.ServeEnvoy(listener, policy, secrets, log, mitmCA)
	}
	log.Record(fmt.Sprintf("airlock-proxy-worker builtin proxy listening on %s", proxyConfig.Listen))
	return worker.NewProxyServerWithOptions(
		policy,
		secrets,
		log,
		worker.ProxyServerOptions{MITMCA: mitmCA, UpstreamTLSConfig: upstreamTLSConfig},
	).Serve(listener)
}

func sourcePolicyByRule(policy worker.CompiledPolicy) map[string]worker.PolicyRef {
	out := map[string]worker.PolicyRef{}
	for _, rule := range policy.Egress {
		if rule.SourcePolicy == nil {
			continue
		}
		out[rule.Name] = *rule.SourcePolicy
	}
	return out
}

func validateControlPlaneAuth(auth string, devToken string, insecureDevMode bool) error {
	switch auth {
	case "spiffe":
		return nil
	case "dev-token":
		if !insecureDevMode {
			return fmt.Errorf("--control-plane-auth dev-token requires --insecure-dev-mode")
		}
		if strings.TrimSpace(devToken) == "" {
			return fmt.Errorf("--control-plane-auth dev-token requires --dev-token")
		}
		return nil
	case "none":
		if !insecureDevMode {
			return fmt.Errorf("--control-plane-auth none requires --insecure-dev-mode")
		}
		return nil
	default:
		return fmt.Errorf("unsupported control-plane auth %q; use spiffe, dev-token, or none", auth)
	}
}

func proxyIPID() (string, error) {
	if podIP := strings.TrimSpace(os.Getenv("POD_IP")); podIP != "" {
		return podIP, nil
	}
	if ip := firstNonLoopbackIP(); ip != "" {
		return ip, nil
	}
	return "", fmt.Errorf("proxy heartbeat requires POD_IP or a non-loopback pod/container IP address")
}

func firstNonLoopbackIP() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			if ipv4 := ip.To4(); ipv4 != nil {
				return ipv4.String()
			}
		}
	}
	return ""
}

type proxyFlags []string

func (f *proxyFlags) String() string {
	return strings.Join(*f, ",")
}

func (f *proxyFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type proxyConfig struct {
	Protocol string
	Mode     string
	Listen   string
}

func resolveProxyConfig(flags proxyFlags) (proxyConfig, error) {
	if len(flags) == 0 {
		return proxyConfig{}, fmt.Errorf("--proxy is required; use protocol:mode[@listen], for example http:builtin@127.0.0.1:18080")
	}
	if len(flags) > 1 {
		return proxyConfig{}, fmt.Errorf("multiple --proxy values are not supported yet")
	}
	return parseProxyConfig(flags[0])
}

func parseProxyConfig(value string) (proxyConfig, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return proxyConfig{}, fmt.Errorf("--proxy cannot be empty")
	}
	protocolMode, listen, hasListen := strings.Cut(value, "@")
	protocol, mode, ok := strings.Cut(protocolMode, ":")
	if !ok || strings.TrimSpace(protocol) == "" || strings.TrimSpace(mode) == "" {
		return proxyConfig{}, fmt.Errorf("--proxy must use protocol:mode[@listen], got %q", value)
	}
	config := proxyConfig{
		Protocol: strings.TrimSpace(protocol),
		Mode:     strings.TrimSpace(mode),
	}
	if hasListen {
		if strings.TrimSpace(listen) == "" {
			return proxyConfig{}, fmt.Errorf("--proxy listen address cannot be empty")
		}
		config.Listen = strings.TrimSpace(listen)
	} else {
		switch config.Protocol + ":" + config.Mode {
		case "http:builtin":
			config.Listen = "127.0.0.1:18080"
		case "http:envoy":
			config.Listen = "127.0.0.1:50051"
		default:
			return proxyConfig{}, fmt.Errorf("no default listen address for --proxy %s:%s", config.Protocol, config.Mode)
		}
	}
	return config, nil
}
