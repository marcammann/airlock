package main

import (
	"flag"
	"os"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
)

type stringList []string

func (l *stringList) String() string {
	return strings.Join(*l, ",")
}

func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

type controlPlaneEnv struct {
	LogFormat                  string        `envconfig:"LOG_FORMAT" default:"json"`
	OTELExporterOTLPEndpoint   string        `envconfig:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	Listen                     string        `envconfig:"LISTEN" default:":8080"`
	AdminListen                string        `envconfig:"ADMIN_LISTEN"`
	AdminTLSCertFile           string        `envconfig:"ADMIN_TLS_CERT"`
	AdminTLSKeyFile            string        `envconfig:"ADMIN_TLS_KEY"`
	HealthListen               string        `envconfig:"HEALTH_LISTEN"`
	MetricsListen              string        `envconfig:"METRICS_LISTEN"`
	AuthConfigPath             string        `envconfig:"AUTH_CONFIG"`
	WorkerAuth                 string        `envconfig:"WORKER_AUTH" default:"spiffe"`
	AdminAuth                  string        `envconfig:"ADMIN_AUTH" default:"spiffe"`
	AdminOIDCIssuer            string        `envconfig:"ADMIN_OIDC_ISSUER"`
	AdminOIDCAudience          string        `envconfig:"ADMIN_OIDC_AUDIENCE"`
	AdminOIDCJWKSURL           string        `envconfig:"ADMIN_OIDC_JWKS_URL"`
	AdminOIDCGroupsClaim       string        `envconfig:"ADMIN_OIDC_GROUPS_CLAIM" default:"groups"`
	AdminOIDCRolesClaim        string        `envconfig:"ADMIN_OIDC_ROLES_CLAIM" default:"roles"`
	HeartbeatStaleThreshold    int           `envconfig:"HEARTBEAT_STALE_THRESHOLD" default:"9"`
	EventLog                   string        `envconfig:"EVENT_LOG" default:"memory"`
	EventLogLimit              int           `envconfig:"EVENT_LOG_LIMIT" default:"1000"`
	EventLogTTL                time.Duration `envconfig:"EVENT_LOG_TTL" default:"24h"`
	EventIngestRate            float64       `envconfig:"EVENT_INGEST_RATE" default:"100"`
	EventIngestBurst           int           `envconfig:"EVENT_INGEST_BURST" default:"500"`
	EventIngestRatePerProxy    float64       `envconfig:"EVENT_INGEST_RATE_PER_PROXY" default:"2"`
	EventIngestBurstPerProxy   int           `envconfig:"EVENT_INGEST_BURST_PER_PROXY" default:"50"`
	Insecure                   bool          `envconfig:"INSECURE" default:"false"`
	SPIFFESocket               string        `envconfig:"SPIFFE_SOCKET"`
	SPIFFETrustDomain          string        `envconfig:"SPIFFE_TRUST_DOMAIN" default:"airlock.local"`
	VaultReconcile             bool          `envconfig:"VAULT_RECONCILE" default:"false"`
	VaultAdminToken            string        `envconfig:"VAULT_ADMIN_TOKEN"`
	VaultAdminTokenFile        string        `envconfig:"VAULT_ADMIN_TOKEN_FILE"`
	KubeSource                 bool          `envconfig:"KUBE_SOURCE" default:"false"`
	KubeNamespace              string        `envconfig:"KUBE_NAMESPACE"`
	KubeReconcileInterval      time.Duration `envconfig:"KUBE_RECONCILE_INTERVAL" default:"10s"`
	KubeLeaderElection         bool          `envconfig:"KUBE_LEADER_ELECTION" default:"true"`
	SPIREReconcile             bool          `envconfig:"SPIRE_RECONCILE" default:"false"`
	SPIREGarbageCollect        bool          `envconfig:"SPIRE_GARBAGE_COLLECT" default:"true"`
	SPIREClassName             string        `envconfig:"SPIRE_CLASS_NAME" default:"spire-system-spire"`
	SPIREPodLabel              string        `envconfig:"SPIRE_PROXY_POD_LABEL" default:"app.kubernetes.io/name"`
	SPIREPodValue              string        `envconfig:"SPIRE_PROXY_POD_VALUE" default:"airlock-proxy-worker"`
	WebhookListen              string        `envconfig:"WEBHOOK_LISTEN"`
	WebhookCertFile            string        `envconfig:"WEBHOOK_CERT_FILE"`
	WebhookKeyFile             string        `envconfig:"WEBHOOK_KEY_FILE"`
	WebhookClientCAFile        string        `envconfig:"WEBHOOK_CLIENT_CA"`
	InjectProxyWorkerImage     string        `envconfig:"INJECT_PROXY_WORKER_IMAGE" default:"airlock-proxy-worker:dev"`
	InjectEnvoyImage           string        `envconfig:"INJECT_ENVOY_IMAGE" default:"envoyproxy/envoy:v1.31.0"`
	InjectControlPlaneURL      string        `envconfig:"INJECT_CONTROL_PLANE_URL" default:"https://airlock-control-plane.airlock-system.svc.cluster.local:8443"`
	InjectControlPlaneServerID string        `envconfig:"INJECT_CONTROL_PLANE_SERVER_ID"`
	InjectUpstreamHost         string        `envconfig:"INJECT_UPSTREAM_HOST" default:"echo-upstream.demo.svc.cluster.local"`
	InjectUpstreamPort         int           `envconfig:"INJECT_UPSTREAM_PORT" default:"8080"`
}

type controlPlaneConfig struct {
	controlPlaneEnv
	PolicyPaths               stringList
	WorkloadPaths             stringList
	SecretProviderConfigPaths stringList
	AdminRBACBindings         stringList
}

type controlPlaneFlagState struct {
	WorkerAuthExplicit bool
	AdminAuthExplicit  bool
}

func loadControlPlaneEnv() (controlPlaneEnv, error) {
	var config controlPlaneEnv
	if err := envconfig.Process("airlock", &config); err != nil {
		return controlPlaneEnv{}, err
	}
	if strings.TrimSpace(config.SPIFFESocket) == "" {
		var spiffeEnv struct {
			Socket string `envconfig:"SPIFFE_ENDPOINT_SOCKET" default:"unix:///run/spire/agent-sockets/spire-agent.sock"`
		}
		if err := envconfig.Process("", &spiffeEnv); err != nil {
			return controlPlaneEnv{}, err
		}
		config.SPIFFESocket = spiffeEnv.Socket
	}
	if strings.TrimSpace(config.KubeNamespace) == "" {
		var podEnv struct {
			Namespace string `envconfig:"POD_NAMESPACE"`
		}
		if err := envconfig.Process("", &podEnv); err != nil {
			return controlPlaneEnv{}, err
		}
		config.KubeNamespace = strings.TrimSpace(podEnv.Namespace)
	}
	if strings.TrimSpace(config.KubeNamespace) == "" {
		config.KubeNamespace = "airlock-system"
	}
	if strings.TrimSpace(config.OTELExporterOTLPEndpoint) == "" {
		var otelEnv struct {
			Endpoint string `envconfig:"OTEL_EXPORTER_OTLP_ENDPOINT"`
		}
		if err := envconfig.Process("", &otelEnv); err != nil {
			return controlPlaneEnv{}, err
		}
		config.OTELExporterOTLPEndpoint = otelEnv.Endpoint
	}
	return config, nil
}

func parseControlPlaneFlags(env controlPlaneEnv) (controlPlaneConfig, controlPlaneFlagState) {
	config := controlPlaneConfig{controlPlaneEnv: env}
	flag.StringVar(&config.LogFormat, "log-format", config.LogFormat, "log format: json or text")
	flag.StringVar(&config.OTELExporterOTLPEndpoint, "otel-exporter-otlp-endpoint", config.OTELExporterOTLPEndpoint, "optional OTLP HTTP trace exporter endpoint")
	flag.StringVar(&config.Listen, "listen", config.Listen, "HTTP listen address")
	flag.StringVar(&config.AdminListen, "admin-listen", config.AdminListen, "optional separate admin API listen address")
	flag.StringVar(&config.AdminTLSCertFile, "admin-tls-cert", config.AdminTLSCertFile, "TLS certificate file for the admin API listener")
	flag.StringVar(&config.AdminTLSKeyFile, "admin-tls-key", config.AdminTLSKeyFile, "TLS private key file for the admin API listener")
	flag.StringVar(&config.HealthListen, "health-listen", config.HealthListen, "optional separate plain HTTP health listen address")
	flag.StringVar(&config.MetricsListen, "metrics-listen", config.MetricsListen, "optional plain HTTP Prometheus metrics listen address")
	flag.StringVar(&config.AuthConfigPath, "auth-config", config.AuthConfigPath, "path to Airlock auth YAML for admin and enrollment auth")
	flag.Var(&config.PolicyPaths, "policy", "path to a reusable AirlockPolicy YAML file; may be repeated")
	flag.Var(&config.WorkloadPaths, "workload", "path to an AirlockWorkload YAML file; may be repeated")
	flag.Var(&config.SecretProviderConfigPaths, "secret-provider-config", "path to a SecretProviderConfig YAML file; may be repeated")
	flag.StringVar(&config.WorkerAuth, "worker-auth", config.WorkerAuth, "worker API auth mode: none or spiffe")
	flag.StringVar(&config.AdminAuth, "admin-auth", config.AdminAuth, "admin API auth mode: none, spiffe, or oidc")
	flag.StringVar(&config.AdminOIDCIssuer, "admin-oidc-issuer", config.AdminOIDCIssuer, "OIDC issuer for admin API bearer tokens")
	flag.StringVar(&config.AdminOIDCAudience, "admin-oidc-audience", config.AdminOIDCAudience, "OIDC audience for admin API bearer tokens")
	flag.StringVar(&config.AdminOIDCJWKSURL, "admin-oidc-jwks-url", config.AdminOIDCJWKSURL, "optional explicit OIDC JWKS URL for admin API bearer tokens")
	flag.StringVar(&config.AdminOIDCGroupsClaim, "admin-oidc-groups-claim", config.AdminOIDCGroupsClaim, "OIDC claim containing admin groups")
	flag.StringVar(&config.AdminOIDCRolesClaim, "admin-oidc-roles-claim", config.AdminOIDCRolesClaim, "OIDC claim containing direct Airlock roles")
	flag.Var(&config.AdminRBACBindings, "admin-rbac-binding", "admin RBAC binding in subject=role[,role] form; subject can be a group, user:<email>, or sub:<subject>")
	flag.IntVar(&config.HeartbeatStaleThreshold, "heartbeat-stale-threshold", config.HeartbeatStaleThreshold, "number of missed proxy heartbeat intervals before marking a proxy stale")
	flag.StringVar(&config.EventLog, "event-log", config.EventLog, "control-plane event log backend: memory or disabled")
	flag.IntVar(&config.EventLogLimit, "event-log-limit", config.EventLogLimit, "maximum in-memory Airlock events to retain")
	flag.DurationVar(&config.EventLogTTL, "event-log-ttl", config.EventLogTTL, "maximum age for in-memory Airlock events")
	flag.Float64Var(&config.EventIngestRate, "event-ingest-rate", config.EventIngestRate, "maximum Airlock events accepted per second across all proxies")
	flag.IntVar(&config.EventIngestBurst, "event-ingest-burst", config.EventIngestBurst, "global burst of Airlock events accepted across all proxies")
	flag.Float64Var(&config.EventIngestRatePerProxy, "event-ingest-rate-per-proxy", config.EventIngestRatePerProxy, "maximum Airlock events accepted per second from each proxy")
	flag.IntVar(&config.EventIngestBurstPerProxy, "event-ingest-burst-per-proxy", config.EventIngestBurstPerProxy, "burst of Airlock events accepted from each proxy")
	flag.BoolVar(&config.Insecure, "insecure", config.Insecure, "allow auth mode none and default unspecified worker/admin auth to none; for local development only")
	flag.StringVar(&config.SPIFFESocket, "spiffe-socket", config.SPIFFESocket, "SPIFFE Workload API socket URI")
	flag.StringVar(&config.SPIFFETrustDomain, "spiffe-trust-domain", config.SPIFFETrustDomain, "SPIFFE trust domain accepted for client SVIDs")
	flag.BoolVar(&config.VaultReconcile, "vault-reconcile", config.VaultReconcile, "reconcile generated Vault policies and JWT roles at startup")
	flag.StringVar(&config.VaultAdminToken, "vault-admin-token", config.VaultAdminToken, "Vault admin token used only for policy/role reconciliation")
	flag.StringVar(&config.VaultAdminTokenFile, "vault-admin-token-file", config.VaultAdminTokenFile, "file containing Vault admin token used only for policy/role reconciliation")
	flag.BoolVar(&config.KubeSource, "kube-source", config.KubeSource, "load AirlockPolicy, AirlockWorkload, and SecretProviderConfig objects from the Kubernetes API")
	flag.StringVar(&config.KubeNamespace, "kube-namespace", config.KubeNamespace, "namespace containing AirlockPolicy, AirlockWorkload, and SecretProviderConfig objects")
	flag.DurationVar(&config.KubeReconcileInterval, "kube-reconcile-interval", config.KubeReconcileInterval, "controller-runtime cache sync period for Kubernetes-backed policy config")
	flag.BoolVar(&config.KubeLeaderElection, "kube-leader-election", config.KubeLeaderElection, "enable Kubernetes leader election for controller-runtime reconciliation")
	flag.BoolVar(&config.SPIREReconcile, "spire-reconcile", config.SPIREReconcile, "reconcile SPIRE ClusterSPIFFEID objects from policy workload identity")
	flag.BoolVar(&config.SPIREGarbageCollect, "spire-garbage-collect", config.SPIREGarbageCollect, "delete stale Airlock-managed SPIRE ClusterSPIFFEID objects during reconciliation")
	flag.StringVar(&config.SPIREClassName, "spire-class-name", config.SPIREClassName, "SPIRE controller className for generated ClusterSPIFFEID objects")
	flag.StringVar(&config.SPIREPodLabel, "spire-proxy-pod-label", config.SPIREPodLabel, "pod label key used to select proxy-worker pods for generated ClusterSPIFFEID objects")
	flag.StringVar(&config.SPIREPodValue, "spire-proxy-pod-value", config.SPIREPodValue, "pod label value used to select proxy-worker pods for generated ClusterSPIFFEID objects")
	flag.StringVar(&config.WebhookListen, "webhook-listen", config.WebhookListen, "optional HTTPS listen address for the Kubernetes mutating admission webhook")
	flag.StringVar(&config.WebhookCertFile, "webhook-cert-file", config.WebhookCertFile, "TLS certificate file for the Kubernetes mutating admission webhook")
	flag.StringVar(&config.WebhookKeyFile, "webhook-key-file", config.WebhookKeyFile, "TLS private key file for the Kubernetes mutating admission webhook")
	flag.StringVar(&config.WebhookClientCAFile, "webhook-client-ca", config.WebhookClientCAFile, "optional CA bundle used to verify kube-apiserver client certificates for the admission webhook")
	flag.StringVar(&config.InjectProxyWorkerImage, "inject-proxy-worker-image", config.InjectProxyWorkerImage, "proxy-worker image injected by the admission webhook")
	flag.StringVar(&config.InjectEnvoyImage, "inject-envoy-image", config.InjectEnvoyImage, "Envoy image injected by the admission webhook")
	flag.StringVar(&config.InjectControlPlaneURL, "inject-control-plane-url", config.InjectControlPlaneURL, "control-plane URL injected into proxy-worker sidecars")
	flag.StringVar(&config.InjectControlPlaneServerID, "inject-control-plane-server-id", config.InjectControlPlaneServerID, "expected control-plane SPIFFE ID injected into proxy-worker sidecars")
	flag.StringVar(&config.InjectUpstreamHost, "inject-upstream-host", config.InjectUpstreamHost, "demo upstream host used by generated Envoy config")
	flag.IntVar(&config.InjectUpstreamPort, "inject-upstream-port", config.InjectUpstreamPort, "demo upstream port used by generated Envoy config")
	flag.Parse()

	var state controlPlaneFlagState
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "worker-auth":
			state.WorkerAuthExplicit = true
		case "admin-auth":
			state.AdminAuthExplicit = true
		}
	})

	appendEnvList(&config.PolicyPaths, "AIRLOCK_POLICY_PATHS", ",")
	appendEnvList(&config.WorkloadPaths, "AIRLOCK_WORKLOAD_PATHS", ",")
	appendEnvList(&config.SecretProviderConfigPaths, "AIRLOCK_SECRET_PROVIDER_CONFIG_PATHS", ",")
	appendEnvList(&config.AdminRBACBindings, "AIRLOCK_ADMIN_RBAC_BINDINGS", ";")
	return config, state
}

func appendEnvList(out *stringList, name string, separator string) {
	if values := strings.TrimSpace(os.Getenv(name)); values != "" {
		for _, value := range strings.Split(values, separator) {
			if value = strings.TrimSpace(value); value != "" {
				*out = append(*out, value)
			}
		}
	}
}
