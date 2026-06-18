package proxyworker

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
)

type proxyWorkerEnv struct {
	LogFormat                string        `envconfig:"LOG_FORMAT" default:"json"`
	OTELExporterOTLPEndpoint string        `envconfig:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	Proxies                  proxyFlags    `envconfig:"PROXY"`
	MetricsListen            string        `envconfig:"METRICS_LISTEN"`
	NoControlPlane           bool          `envconfig:"NO_CONTROL_PLANE" default:"false"`
	PolicyPath               string        `envconfig:"POLICY_PATH"`
	MITMCACert               string        `envconfig:"MITM_CA_CERT"`
	MITMCAKey                string        `envconfig:"MITM_CA_KEY"`
	UpstreamCACert           string        `envconfig:"UPSTREAM_CA_CERT"`
	MaxResponseBytes         int64         `envconfig:"MAX_RESPONSE_BYTES" default:"16777216"`
	SecretFileRoot           string        `envconfig:"SECRET_FILE_ROOT"`
	ControlPlaneURL          string        `envconfig:"CONTROL_PLANE_URL"`
	ControlPlaneAuth         string        `envconfig:"CONTROL_PLANE_AUTH" default:"spiffe"`
	Insecure                 bool          `envconfig:"INSECURE" default:"false"`
	WorkloadIdentity         string        `envconfig:"WORKLOAD_IDENTITY"`
	EnrollmentToken          string        `envconfig:"ENROLLMENT_TOKEN"`
	EnrollmentTokenFile      string        `envconfig:"ENROLLMENT_TOKEN_FILE"`
	ControlPlaneServerID     string        `envconfig:"CONTROL_PLANE_SERVER_ID"`
	SPIFFESocket             string        `envconfig:"SPIFFE_SOCKET"`
	HeartbeatInterval        time.Duration `envconfig:"HEARTBEAT_INTERVAL" default:"10s"`
	PolicyPollInterval       time.Duration `envconfig:"POLICY_POLL_INTERVAL" default:"30s"`
	EventReport              string        `envconfig:"EVENT_REPORT" default:"control-plane"`
	EventEndpoint            string        `envconfig:"EVENT_ENDPOINT"`
	EventReportRate          float64       `envconfig:"EVENT_REPORT_RATE" default:"1"`
	EventReportBurst         int           `envconfig:"EVENT_REPORT_BURST" default:"20"`
	EventReportPendingLimit  int           `envconfig:"EVENT_REPORT_PENDING_LIMIT" default:"256"`
	EventReportFlushInterval time.Duration `envconfig:"EVENT_REPORT_FLUSH_INTERVAL" default:"1s"`
}

type proxyWorkerConfig struct {
	LogFormat                string
	OTELExporterOTLPEndpoint string
	Proxies                  proxyFlags
	Proxy                    proxyConfig
	MetricsListen            string
	NoControlPlane           bool
	PolicyPath               string
	MITMCACert               string
	MITMCAKey                string
	UpstreamCACert           string
	MaxResponseBytes         int64
	SecretFileRoot           string
	ControlPlaneURL          string
	ControlPlaneAuth         string
	ControlPlaneAuthExplicit bool
	Insecure                 bool
	WorkloadIdentity         string
	EnrollmentToken          string
	EnrollmentTokenFile      string
	ControlPlaneServerID     string
	SPIFFESocket             string
	HeartbeatInterval        time.Duration
	PolicyPollInterval       time.Duration
	EventReport              string
	EventEndpoint            string
	EventReportRate          float64
	EventReportBurst         int
	EventReportPendingLimit  int
	EventReportFlushInterval time.Duration
}

func loadProxyWorkerEnv() (proxyWorkerEnv, error) {
	var config proxyWorkerEnv
	if err := envconfig.Process("airlock", &config); err != nil {
		return proxyWorkerEnv{}, err
	}
	if strings.TrimSpace(config.SPIFFESocket) == "" {
		var spiffeEnv struct {
			Socket string `envconfig:"SPIFFE_ENDPOINT_SOCKET"`
		}
		if err := envconfig.Process("", &spiffeEnv); err != nil {
			return proxyWorkerEnv{}, err
		}
		config.SPIFFESocket = spiffeEnv.Socket
	}
	if strings.TrimSpace(config.OTELExporterOTLPEndpoint) == "" {
		var otelEnv struct {
			Endpoint string `envconfig:"OTEL_EXPORTER_OTLP_ENDPOINT"`
		}
		if err := envconfig.Process("", &otelEnv); err != nil {
			return proxyWorkerEnv{}, err
		}
		config.OTELExporterOTLPEndpoint = otelEnv.Endpoint
	}
	return config, nil
}

func parseProxyWorkerFlags(env proxyWorkerEnv) (proxyWorkerConfig, error) {
	var config proxyWorkerConfig
	config.Proxies = env.Proxies
	logFormat := flag.String("log-format", env.LogFormat, "log format: json or text")
	otelExporterOTLPEndpoint := flag.String("otel-exporter-otlp-endpoint", env.OTELExporterOTLPEndpoint, "optional OTLP HTTP trace exporter endpoint")
	metricsListen := flag.String("metrics-listen", env.MetricsListen, "optional plain HTTP Prometheus metrics listen address")
	noControlPlane := flag.Bool("no-control-plane", env.NoControlPlane, "load compiled policy from --policy instead of the control plane")
	policyPath := flag.String("policy", env.PolicyPath, "local compiled policy YAML or JSON path")
	mitmCACert := flag.String("mitm-ca-cert", env.MITMCACert, "public CA certificate used for HTTPS interception")
	mitmCAKey := flag.String("mitm-ca-key", env.MITMCAKey, "private CA key used for HTTPS interception")
	upstreamCACert := flag.String("upstream-ca-cert", env.UpstreamCACert, "optional CA certificate bundle used to verify upstream TLS in builtin mode")
	maxResponseBytes := flag.Int64("max-response-bytes", env.MaxResponseBytes, "maximum upstream response bytes forwarded by the builtin proxy")
	secretFileRoot := flag.String("secret-file-root", env.SecretFileRoot, "restrict file-based secrets to this directory")
	controlPlaneURL := flag.String("control-plane-url", env.ControlPlaneURL, "control-plane policy API URL")
	controlPlaneAuth := flag.String("control-plane-auth", env.ControlPlaneAuth, "control-plane auth mode: spiffe or enrollment; enrollment is inferred when --enrollment-token-file or --enrollment-token is set")
	insecure := flag.Bool("insecure", env.Insecure, "fetch policy, send heartbeats, and report events without authenticating to the control plane; for local development only")
	workloadIdentity := flag.String("workload-identity", env.WorkloadIdentity, "workload SPIFFE ID")
	enrollmentToken := flag.String("enrollment-token", env.EnrollmentToken, "one-time enrollment token for control-plane policy bootstrap")
	enrollmentTokenFile := flag.String("enrollment-token-file", env.EnrollmentTokenFile, "file containing a one-time enrollment token for control-plane policy bootstrap")
	controlPlaneServerID := flag.String("control-plane-server-id", env.ControlPlaneServerID, "reserved for SPIFFE control-plane auth")
	spiffeSocket := flag.String("spiffe-socket", env.SPIFFESocket, "reserved SPIFFE workload API socket URI")
	heartbeatInterval := flag.Duration("heartbeat-interval", env.HeartbeatInterval, "interval for proxy heartbeat reports; set 0 to disable")
	policyPollInterval := flag.Duration("policy-poll-interval", env.PolicyPollInterval, "interval for refreshing control-plane policy; set 0 to disable")
	eventReport := flag.String("event-report", env.EventReport, "Airlock event reporting mode: control-plane or disabled")
	eventEndpoint := flag.String("event-endpoint", env.EventEndpoint, "Airlock event ingest URL; defaults to the control plane /v1/events endpoint")
	eventReportRate := flag.Float64("event-report-rate", env.EventReportRate, "maximum Airlock event reports sent per second")
	eventReportBurst := flag.Int("event-report-burst", env.EventReportBurst, "burst of Airlock event reports sent by the proxy")
	eventReportPendingLimit := flag.Int("event-report-pending-limit", env.EventReportPendingLimit, "maximum unique Airlock events aggregated before local suppression")
	eventReportFlushInterval := flag.Duration("event-report-flush-interval", env.EventReportFlushInterval, "interval for flushing aggregated Airlock events")

	flag.Var(&config.Proxies, "proxy", "proxy listener in protocol:mode[@listen] form, for example http:builtin@127.0.0.1:18080")
	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "control-plane-auth" {
			config.ControlPlaneAuthExplicit = true
		}
	})
	if hasEnrollmentTokenInput(*enrollmentToken, *enrollmentTokenFile) && !config.ControlPlaneAuthExplicit {
		*controlPlaneAuth = "enrollment"
	}

	proxy, err := resolveProxyConfig(config.Proxies)
	if err != nil {
		return proxyWorkerConfig{}, err
	}
	if proxy.Protocol != "http" || (proxy.Mode != "builtin" && proxy.Mode != "envoy") {
		return proxyWorkerConfig{}, fmt.Errorf("go worker currently supports --proxy http:builtin and --proxy http:envoy; %s:%s is the next parity slice", proxy.Protocol, proxy.Mode)
	}
	if proxy.Mode == "envoy" && *upstreamCACert != "" {
		return proxyWorkerConfig{}, fmt.Errorf("--upstream-ca-cert is for http:builtin; configure Envoy upstream TLS trust in the Envoy bootstrap")
	}

	config.LogFormat = *logFormat
	config.OTELExporterOTLPEndpoint = *otelExporterOTLPEndpoint
	config.Proxy = proxy
	config.MetricsListen = *metricsListen
	config.NoControlPlane = *noControlPlane
	config.PolicyPath = *policyPath
	config.MITMCACert = *mitmCACert
	config.MITMCAKey = *mitmCAKey
	config.UpstreamCACert = *upstreamCACert
	config.MaxResponseBytes = *maxResponseBytes
	config.SecretFileRoot = *secretFileRoot
	config.ControlPlaneURL = *controlPlaneURL
	config.ControlPlaneAuth = *controlPlaneAuth
	config.Insecure = *insecure
	config.WorkloadIdentity = *workloadIdentity
	config.EnrollmentToken = *enrollmentToken
	config.EnrollmentTokenFile = *enrollmentTokenFile
	config.ControlPlaneServerID = *controlPlaneServerID
	config.SPIFFESocket = *spiffeSocket
	config.HeartbeatInterval = *heartbeatInterval
	config.PolicyPollInterval = *policyPollInterval
	config.EventReport = *eventReport
	config.EventEndpoint = *eventEndpoint
	config.EventReportRate = *eventReportRate
	config.EventReportBurst = *eventReportBurst
	config.EventReportPendingLimit = *eventReportPendingLimit
	config.EventReportFlushInterval = *eventReportFlushInterval
	return config, nil
}

type proxyFlags []string

func (f *proxyFlags) String() string {
	return strings.Join(*f, ",")
}

func (f *proxyFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func (f *proxyFlags) Decode(value string) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			*f = append(*f, item)
		}
	}
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
