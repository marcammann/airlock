package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/marcammann/airlock/internal/controlplane"
	"github.com/marcammann/airlock/internal/policy"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type stringList []string

func (l *stringList) String() string {
	return strings.Join(*l, ",")
}

func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var listen string
	var adminListen string
	var healthListen string
	var policyPaths stringList
	var workloadPaths stringList
	var secretProviderConfigPaths stringList
	var workerAuth string
	var workerDevToken string
	var adminAuth string
	var adminDevToken string
	var adminOIDCIssuer string
	var adminOIDCAudience string
	var adminOIDCJWKSURL string
	var adminOIDCGroupsClaim string
	var adminOIDCRolesClaim string
	var adminRBACBindings stringList
	var heartbeatStaleThreshold int
	var eventLog string
	var eventLogLimit int
	var eventLogTTL time.Duration
	var eventIngestRate float64
	var eventIngestBurst int
	var eventIngestRatePerProxy float64
	var eventIngestBurstPerProxy int
	var insecureDevMode bool
	var spiffeSocket string
	var spiffeTrustDomain string
	var vaultReconcile bool
	var vaultAdminToken string
	var vaultAdminTokenFile string
	var kubeSource bool
	var kubeNamespace string
	var kubeReconcileInterval time.Duration
	var spireReconcile bool
	var spireGarbageCollect bool
	var spireClassName string
	var spirePodLabel string
	var spirePodValue string
	var webhookListen string
	var webhookCertFile string
	var webhookKeyFile string
	var injectProxyWorkerImage string
	var injectEnvoyImage string
	var injectControlPlaneURL string
	var injectControlPlaneServerID string
	var injectUpstreamHost string
	var injectUpstreamPort int

	flag.StringVar(&listen, "listen", envOrDefault("AIRLOCK_LISTEN", ":8080"), "HTTP listen address")
	flag.StringVar(&adminListen, "admin-listen", os.Getenv("AIRLOCK_ADMIN_LISTEN"), "optional separate admin API listen address")
	flag.StringVar(&healthListen, "health-listen", os.Getenv("AIRLOCK_HEALTH_LISTEN"), "optional separate plain HTTP health listen address")
	flag.Var(&policyPaths, "policy", "path to a reusable AirlockPolicy YAML file; may be repeated")
	flag.Var(&workloadPaths, "workload", "path to an AirlockWorkload YAML file; may be repeated")
	flag.Var(&secretProviderConfigPaths, "secret-provider-config", "path to a SecretProviderConfig YAML file; may be repeated")
	flag.StringVar(&workerAuth, "worker-auth", envOrDefault("AIRLOCK_WORKER_AUTH", "spiffe"), "worker API auth mode: none, dev-token, or spiffe")
	flag.StringVar(&adminAuth, "admin-auth", envOrDefault("AIRLOCK_ADMIN_AUTH", "spiffe"), "admin API auth mode: none, dev-token, spiffe, or oidc")
	flag.StringVar(&workerDevToken, "worker-dev-token", os.Getenv("AIRLOCK_WORKER_DEV_TOKEN"), "worker API development bearer token")
	flag.StringVar(&adminDevToken, "admin-dev-token", os.Getenv("AIRLOCK_ADMIN_DEV_TOKEN"), "admin API development bearer token")
	flag.StringVar(&adminOIDCIssuer, "admin-oidc-issuer", os.Getenv("AIRLOCK_ADMIN_OIDC_ISSUER"), "OIDC issuer for admin API bearer tokens")
	flag.StringVar(&adminOIDCAudience, "admin-oidc-audience", os.Getenv("AIRLOCK_ADMIN_OIDC_AUDIENCE"), "OIDC audience for admin API bearer tokens")
	flag.StringVar(&adminOIDCJWKSURL, "admin-oidc-jwks-url", os.Getenv("AIRLOCK_ADMIN_OIDC_JWKS_URL"), "optional explicit OIDC JWKS URL for admin API bearer tokens")
	flag.StringVar(&adminOIDCGroupsClaim, "admin-oidc-groups-claim", envOrDefault("AIRLOCK_ADMIN_OIDC_GROUPS_CLAIM", "groups"), "OIDC claim containing admin groups")
	flag.StringVar(&adminOIDCRolesClaim, "admin-oidc-roles-claim", envOrDefault("AIRLOCK_ADMIN_OIDC_ROLES_CLAIM", "roles"), "OIDC claim containing direct Airlock roles")
	flag.Var(&adminRBACBindings, "admin-rbac-binding", "admin RBAC binding in subject=role[,role] form; subject can be a group, user:<email>, or sub:<subject>")
	flag.IntVar(&heartbeatStaleThreshold, "heartbeat-stale-threshold", envIntOrDefault("AIRLOCK_HEARTBEAT_STALE_THRESHOLD", 9), "number of missed proxy heartbeat intervals before marking a proxy stale")
	flag.StringVar(&eventLog, "event-log", envOrDefault("AIRLOCK_EVENT_LOG", "memory"), "control-plane event log backend: memory or disabled")
	flag.IntVar(&eventLogLimit, "event-log-limit", envIntOrDefault("AIRLOCK_EVENT_LOG_LIMIT", 1000), "maximum in-memory Airlock events to retain")
	flag.DurationVar(&eventLogTTL, "event-log-ttl", envDurationOrDefault("AIRLOCK_EVENT_LOG_TTL", 24*time.Hour), "maximum age for in-memory Airlock events")
	flag.Float64Var(&eventIngestRate, "event-ingest-rate", envFloatOrDefault("AIRLOCK_EVENT_INGEST_RATE", 100), "maximum Airlock events accepted per second across all proxies")
	flag.IntVar(&eventIngestBurst, "event-ingest-burst", envIntOrDefault("AIRLOCK_EVENT_INGEST_BURST", 500), "global burst of Airlock events accepted across all proxies")
	flag.Float64Var(&eventIngestRatePerProxy, "event-ingest-rate-per-proxy", envFloatOrDefault("AIRLOCK_EVENT_INGEST_RATE_PER_PROXY", 2), "maximum Airlock events accepted per second from each proxy")
	flag.IntVar(&eventIngestBurstPerProxy, "event-ingest-burst-per-proxy", envIntOrDefault("AIRLOCK_EVENT_INGEST_BURST_PER_PROXY", 50), "burst of Airlock events accepted from each proxy")
	flag.BoolVar(&insecureDevMode, "insecure-dev-mode", envBool("AIRLOCK_INSECURE_DEV_MODE"), "allow insecure development auth modes such as none and dev-token")
	flag.StringVar(&spiffeSocket, "spiffe-socket", envOrDefault("SPIFFE_ENDPOINT_SOCKET", "unix:///run/spire/agent-sockets/spire-agent.sock"), "SPIFFE Workload API socket URI")
	flag.StringVar(&spiffeTrustDomain, "spiffe-trust-domain", envOrDefault("AIRLOCK_SPIFFE_TRUST_DOMAIN", "airlock.local"), "SPIFFE trust domain accepted for client SVIDs")
	flag.BoolVar(&vaultReconcile, "vault-reconcile", envBool("AIRLOCK_VAULT_RECONCILE"), "reconcile generated Vault policies and JWT roles at startup")
	flag.StringVar(&vaultAdminToken, "vault-admin-token", os.Getenv("AIRLOCK_VAULT_ADMIN_TOKEN"), "Vault admin token used only for policy/role reconciliation")
	flag.StringVar(&vaultAdminTokenFile, "vault-admin-token-file", os.Getenv("AIRLOCK_VAULT_ADMIN_TOKEN_FILE"), "file containing Vault admin token used only for policy/role reconciliation")
	flag.BoolVar(&kubeSource, "kube-source", envBool("AIRLOCK_KUBE_SOURCE"), "load AirlockPolicy, AirlockWorkload, and SecretProviderConfig objects from the Kubernetes API")
	flag.StringVar(&kubeNamespace, "kube-namespace", envOrDefault("AIRLOCK_KUBE_NAMESPACE", envOrDefault("POD_NAMESPACE", "airlock-system")), "namespace containing AirlockPolicy, AirlockWorkload, and SecretProviderConfig objects")
	flag.DurationVar(&kubeReconcileInterval, "kube-reconcile-interval", envDurationOrDefault("AIRLOCK_KUBE_RECONCILE_INTERVAL", 10*time.Second), "interval for refreshing Kubernetes-backed policy config")
	flag.BoolVar(&spireReconcile, "spire-reconcile", envBool("AIRLOCK_SPIRE_RECONCILE"), "reconcile SPIRE ClusterSPIFFEID objects from policy workload identity")
	flag.BoolVar(&spireGarbageCollect, "spire-garbage-collect", envBoolOrDefault("AIRLOCK_SPIRE_GARBAGE_COLLECT", true), "delete stale Airlock-managed SPIRE ClusterSPIFFEID objects during reconciliation")
	flag.StringVar(&spireClassName, "spire-class-name", envOrDefault("AIRLOCK_SPIRE_CLASS_NAME", "spire-system-spire"), "SPIRE controller className for generated ClusterSPIFFEID objects")
	flag.StringVar(&spirePodLabel, "spire-proxy-pod-label", envOrDefault("AIRLOCK_SPIRE_PROXY_POD_LABEL", "app.kubernetes.io/name"), "pod label key used to select proxy-worker pods for generated ClusterSPIFFEID objects")
	flag.StringVar(&spirePodValue, "spire-proxy-pod-value", envOrDefault("AIRLOCK_SPIRE_PROXY_POD_VALUE", "airlock-proxy-worker"), "pod label value used to select proxy-worker pods for generated ClusterSPIFFEID objects")
	flag.StringVar(&webhookListen, "webhook-listen", os.Getenv("AIRLOCK_WEBHOOK_LISTEN"), "optional HTTPS listen address for the Kubernetes mutating admission webhook")
	flag.StringVar(&webhookCertFile, "webhook-cert-file", os.Getenv("AIRLOCK_WEBHOOK_CERT_FILE"), "TLS certificate file for the Kubernetes mutating admission webhook")
	flag.StringVar(&webhookKeyFile, "webhook-key-file", os.Getenv("AIRLOCK_WEBHOOK_KEY_FILE"), "TLS private key file for the Kubernetes mutating admission webhook")
	flag.StringVar(&injectProxyWorkerImage, "inject-proxy-worker-image", envOrDefault("AIRLOCK_INJECT_PROXY_WORKER_IMAGE", "airlock-proxy-worker:dev"), "proxy-worker image injected by the admission webhook")
	flag.StringVar(&injectEnvoyImage, "inject-envoy-image", envOrDefault("AIRLOCK_INJECT_ENVOY_IMAGE", "envoyproxy/envoy:v1.31.0"), "Envoy image injected by the admission webhook")
	flag.StringVar(&injectControlPlaneURL, "inject-control-plane-url", envOrDefault("AIRLOCK_INJECT_CONTROL_PLANE_URL", "https://airlock-control-plane.airlock-system.svc.cluster.local:8443"), "control-plane URL injected into proxy-worker sidecars")
	flag.StringVar(&injectControlPlaneServerID, "inject-control-plane-server-id", os.Getenv("AIRLOCK_INJECT_CONTROL_PLANE_SERVER_ID"), "expected control-plane SPIFFE ID injected into proxy-worker sidecars")
	flag.StringVar(&injectUpstreamHost, "inject-upstream-host", envOrDefault("AIRLOCK_INJECT_UPSTREAM_HOST", "echo-upstream.demo.svc.cluster.local"), "demo upstream host used by generated Envoy config")
	flag.IntVar(&injectUpstreamPort, "inject-upstream-port", envIntOrDefault("AIRLOCK_INJECT_UPSTREAM_PORT", 8080), "demo upstream port used by generated Envoy config")
	flag.Parse()

	if envPaths := strings.TrimSpace(os.Getenv("AIRLOCK_POLICY_PATHS")); envPaths != "" {
		for _, path := range strings.Split(envPaths, ",") {
			if path = strings.TrimSpace(path); path != "" {
				policyPaths = append(policyPaths, path)
			}
		}
	}
	if envPaths := strings.TrimSpace(os.Getenv("AIRLOCK_WORKLOAD_PATHS")); envPaths != "" {
		for _, path := range strings.Split(envPaths, ",") {
			if path = strings.TrimSpace(path); path != "" {
				workloadPaths = append(workloadPaths, path)
			}
		}
	}
	if envPaths := strings.TrimSpace(os.Getenv("AIRLOCK_SECRET_PROVIDER_CONFIG_PATHS")); envPaths != "" {
		for _, path := range strings.Split(envPaths, ",") {
			if path = strings.TrimSpace(path); path != "" {
				secretProviderConfigPaths = append(secretProviderConfigPaths, path)
			}
		}
	}
	if envBindings := strings.TrimSpace(os.Getenv("AIRLOCK_ADMIN_RBAC_BINDINGS")); envBindings != "" {
		for _, binding := range strings.Split(envBindings, ";") {
			if binding = strings.TrimSpace(binding); binding != "" {
				adminRBACBindings = append(adminRBACBindings, binding)
			}
		}
	}

	if !kubeSource && len(policyPaths) == 0 {
		return fmt.Errorf("at least one --policy or AIRLOCK_POLICY_PATHS entry is required")
	}
	if !kubeSource && len(workloadPaths) == 0 {
		return fmt.Errorf("at least one --workload or AIRLOCK_WORKLOAD_PATHS entry is required")
	}

	ctx := context.Background()
	var store *controlplane.PolicyStore
	var kubeStatusUpdates []controlplane.KubernetesPolicyStatusUpdate
	var err error
	kubeOpts := controlplane.DefaultKubernetesPolicySourceOptions(kubeNamespace)
	spireOpts := controlplane.SPIREReconcileOptions{
		Kubernetes:     kubeOpts,
		ClassName:      spireClassName,
		PodLabel:       spirePodLabel,
		PodValue:       spirePodValue,
		GarbageCollect: spireGarbageCollect,
		Audit:          os.Stderr,
	}
	if kubeSource {
		store, kubeStatusUpdates, err = controlplane.LoadPolicyStoreFromKubernetes(ctx, kubeOpts)
	} else {
		store, err = controlplane.LoadPolicyStoreWithSecretProviderConfigs(policyPaths, workloadPaths, secretProviderConfigPaths)
	}
	if err != nil {
		return err
	}

	spireReady := !spireReconcile
	if spireReconcile {
		result, err := controlplane.ReconcileSPIRE(ctx, store, spireOpts)
		if err != nil {
			return err
		}
		spireReady = true
		log.Printf("airlock-control-plane reconciled SPIRE intent: clusterSPIFFEIDs=%d deletedClusterSPIFFEIDs=%d", result.ClusterSPIFFEIDs, result.DeletedClusterSPIFFEIDs)
	}

	var vaultToken string
	vaultReady := !vaultReconcile
	if vaultReconcile {
		vaultToken, err = resolveSecretValue(vaultAdminToken, vaultAdminTokenFile)
		if err != nil {
			return err
		}
		result, err := controlplane.ReconcileVault(context.Background(), store, controlplane.VaultReconcileOptions{
			AdminToken: vaultToken,
			Audit:      os.Stderr,
		})
		if err != nil {
			return err
		}
		vaultReady = true
		log.Printf("airlock-control-plane reconciled Vault intent: policies=%d roles=%d", result.Policies, result.Roles)
	}
	if kubeSource {
		patchKubernetesStatuses(ctx, kubeOpts, kubeStatusUpdates, spireReady, vaultReady)
	}

	workerMode := controlplane.AuthMode(workerAuth)
	adminMode := controlplane.AuthMode(adminAuth)
	if err := validateAuthConfig(workerMode, workerDevToken, "worker", insecureDevMode); err != nil {
		return err
	}
	if adminListen != "" {
		if err := validateAuthConfig(adminMode, adminDevToken, "admin", insecureDevMode); err != nil {
			return err
		}
	}
	if insecureDevMode {
		log.Printf("airlock-control-plane insecure development auth modes are enabled")
	}
	if heartbeatStaleThreshold <= 0 {
		return fmt.Errorf("--heartbeat-stale-threshold must be greater than zero")
	}
	eventLogMode := controlplane.EventLogMode(strings.TrimSpace(eventLog))
	switch eventLogMode {
	case controlplane.EventLogMemory, controlplane.EventLogDisabled:
	default:
		return fmt.Errorf("--event-log must be memory or disabled")
	}
	if eventLogLimit <= 0 {
		return fmt.Errorf("--event-log-limit must be greater than zero")
	}
	if eventLogTTL <= 0 {
		return fmt.Errorf("--event-log-ttl must be greater than zero")
	}
	if eventIngestRate <= 0 {
		return fmt.Errorf("--event-ingest-rate must be greater than zero")
	}
	if eventIngestBurst <= 0 {
		return fmt.Errorf("--event-ingest-burst must be greater than zero")
	}
	if eventIngestRatePerProxy <= 0 {
		return fmt.Errorf("--event-ingest-rate-per-proxy must be greater than zero")
	}
	if eventIngestBurstPerProxy <= 0 {
		return fmt.Errorf("--event-ingest-burst-per-proxy must be greater than zero")
	}
	var adminOIDC *controlplane.OIDCAuthenticator
	if adminListen != "" && adminMode == controlplane.AuthModeOIDC {
		adminOIDC, err = controlplane.NewOIDCAuthenticator(ctx, controlplane.OIDCConfig{
			Issuer:      adminOIDCIssuer,
			Audience:    adminOIDCAudience,
			JWKSURL:     adminOIDCJWKSURL,
			GroupsClaim: adminOIDCGroupsClaim,
			RolesClaim:  adminOIDCRolesClaim,
		})
		if err != nil {
			return err
		}
	}
	roleBindings, err := parseRBACBindings(adminRBACBindings)
	if err != nil {
		return err
	}
	rbac := controlplane.NewRBACAuthorizer(controlplane.RBACConfig{RoleBindings: roleBindings})
	server := controlplane.NewServerWithOptions(store, controlplane.ServerOptions{
		WorkerAuthMode:           workerMode,
		WorkerDevToken:           workerDevToken,
		AdminAuthMode:            adminMode,
		AdminDevToken:            adminDevToken,
		AdminOIDC:                adminOIDC,
		AdminRBAC:                rbac,
		HeartbeatStaleThreshold:  heartbeatStaleThreshold,
		EventLogMode:             eventLogMode,
		EventLogLimit:            eventLogLimit,
		EventLogTTL:              eventLogTTL,
		EventIngestRate:          eventIngestRate,
		EventIngestBurst:         eventIngestBurst,
		EventIngestRatePerProxy:  eventIngestRatePerProxy,
		EventIngestBurstPerProxy: eventIngestBurstPerProxy,
		AllowInsecureDevAuth:     insecureDevMode,
		Audit:                    os.Stderr,
	})
	if kubeSource {
		go runKubernetesReconcileLoop(ctx, server, kubeOpts, spireOpts, spireReconcile, vaultReconcile, vaultToken, kubeReconcileInterval)
	}
	if webhookListen != "" {
		if strings.TrimSpace(webhookCertFile) == "" || strings.TrimSpace(webhookKeyFile) == "" {
			return fmt.Errorf("--webhook-cert-file and --webhook-key-file are required when --webhook-listen is set")
		}
		go func() {
			opts := controlplane.InjectionOptions{
				TrustDomain:          spiffeTrustDomain,
				ProxyWorkerImage:     injectProxyWorkerImage,
				EnvoyImage:           injectEnvoyImage,
				ControlPlaneURL:      injectControlPlaneURL,
				ControlPlaneServerID: injectControlPlaneServerID,
				SPIFFESocket:         spiffeSocket,
				UpstreamHost:         injectUpstreamHost,
				UpstreamPort:         injectUpstreamPort,
			}
			log.Printf("airlock-control-plane injection webhook listening on %s", webhookListen)
			err := http.ListenAndServeTLS(webhookListen, webhookCertFile, webhookKeyFile, controlplane.NewInjectionWebhookHandler(server, opts))
			if err != nil {
				log.Printf("injection webhook stopped: %v", err)
			}
		}()
	}
	if healthListen != "" {
		go func() {
			log.Printf("airlock-control-plane health listening on %s", healthListen)
			if err := http.ListenAndServe(healthListen, server.HealthHandler()); err != nil {
				log.Printf("health server stopped: %v", err)
			}
		}()
	}
	if adminListen != "" {
		go func() {
			log.Printf("airlock-control-plane admin API listening on %s with admin_auth=%s", adminListen, adminMode)
			if err := http.ListenAndServe(adminListen, server.AdminHandler()); err != nil {
				log.Printf("admin server stopped: %v", err)
			}
		}()
	}

	switch workerMode {
	case controlplane.AuthModeNone, controlplane.AuthModeDevToken:
		log.Printf("airlock-control-plane listening on %s with %d policy mapping(s), worker_auth=%s admin_auth=%s", listen, store.Len(), workerMode, adminMode)
		return http.ListenAndServe(listen, server.WorkerHandler())
	case controlplane.AuthModeSPIFFE:
		return serveSPIFFE(listen, spiffeSocket, spiffeTrustDomain, server)
	default:
		return fmt.Errorf("unsupported worker auth mode %q", workerAuth)
	}
}

func envOrDefault(name string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

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

func validateAuthConfig(mode controlplane.AuthMode, token string, name string, insecureDevMode bool) error {
	switch mode {
	case controlplane.AuthModeNone:
		if !insecureDevMode {
			return fmt.Errorf("%s auth mode none requires --insecure-dev-mode", name)
		}
		return nil
	case controlplane.AuthModeSPIFFE:
		return nil
	case controlplane.AuthModeDevToken:
		if !insecureDevMode {
			return fmt.Errorf("%s auth mode dev-token requires --insecure-dev-mode", name)
		}
		if strings.TrimSpace(token) == "" {
			return fmt.Errorf("%s auth mode dev-token requires a non-empty token", name)
		}
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

func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "t", "true", "y", "yes", "on":
		return true
	default:
		return false
	}
}

func envBoolOrDefault(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "t", "true", "y", "yes", "on":
		return true
	case "0", "f", "false", "n", "no", "off":
		return false
	default:
		return fallback
	}
}

func envDurationOrDefault(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envIntOrDefault(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	var parsed int
	if _, err := fmt.Sscanf(value, "%d", &parsed); err != nil {
		return fallback
	}
	return parsed
}

func envFloatOrDefault(name string, fallback float64) float64 {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	var parsed float64
	if _, err := fmt.Sscanf(value, "%f", &parsed); err != nil {
		return fallback
	}
	return parsed
}

func resolveSecretValue(value string, path string) (string, error) {
	value = strings.TrimSpace(value)
	path = strings.TrimSpace(path)
	if value != "" {
		return value, nil
	}
	if path == "" {
		return "", fmt.Errorf("vault admin token is required when Vault reconciliation is enabled")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open Vault admin token file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read Vault admin token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("Vault admin token file is empty")
	}
	return token, nil
}

func runKubernetesReconcileLoop(ctx context.Context, server *controlplane.Server, opts controlplane.KubernetesPolicySourceOptions, spireOpts controlplane.SPIREReconcileOptions, spireReconcile bool, vaultReconcile bool, vaultToken string, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			store, updates, err := controlplane.LoadPolicyStoreFromKubernetes(ctx, opts)
			if err != nil {
				log.Printf("kubernetes reconciliation failed: %v", err)
				continue
			}
			spireReady := !spireReconcile
			if spireReconcile {
				result, err := controlplane.ReconcileSPIRE(ctx, store, spireOpts)
				if err != nil {
					log.Printf("SPIRE reconciliation failed: %v", err)
					patchKubernetesStatuses(ctx, opts, updates, false, !vaultReconcile)
					continue
				}
				spireReady = true
				log.Printf("airlock-control-plane reconciled SPIRE intent: clusterSPIFFEIDs=%d deletedClusterSPIFFEIDs=%d", result.ClusterSPIFFEIDs, result.DeletedClusterSPIFFEIDs)
			}

			vaultReady := !vaultReconcile
			if vaultReconcile {
				result, err := controlplane.ReconcileVault(ctx, store, controlplane.VaultReconcileOptions{
					AdminToken: vaultToken,
					Audit:      os.Stderr,
				})
				if err != nil {
					log.Printf("vault reconciliation failed: %v", err)
					patchKubernetesStatuses(ctx, opts, updates, spireReady, false)
					continue
				}
				vaultReady = true
				log.Printf("airlock-control-plane reconciled Kubernetes intent: policies=%d vaultPolicies=%d vaultRoles=%d", store.Len(), result.Policies, result.Roles)
			}
			server.ReplaceStore(store)
			patchKubernetesStatuses(ctx, opts, updates, spireReady, vaultReady)
		}
	}
}

func patchKubernetesStatuses(ctx context.Context, opts controlplane.KubernetesPolicySourceOptions, updates []controlplane.KubernetesPolicyStatusUpdate, spireReady bool, vaultReady bool) {
	for _, update := range updates {
		status := update.Status
		status.Spire.Ready = spireReady
		status.Vault.Ready = vaultReady
		if len(status.Conditions) == 0 {
			status.Conditions = []policy.StatusCondition{{Type: "Ready"}}
		}
		if spireReady && vaultReady {
			status.Conditions[0].Status = "True"
			status.Conditions[0].Reason = "Reconciled"
			status.Conditions[0].Message = ""
		} else {
			status.Conditions[0].Status = "False"
			status.Conditions[0].Reason = "Reconciling"
		}
		if err := controlplane.PatchAirlockWorkloadStatus(ctx, opts, update.Workload, status); err != nil {
			log.Printf("patch AirlockWorkload status %s/%s: %v", update.Workload.Metadata.Namespace, update.Workload.Metadata.Name, err)
		}
	}
}

func serveSPIFFE(listen string, socket string, trustDomain string, server *controlplane.Server) error {
	ctx := context.Background()
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socket)))
	if err != nil {
		return fmt.Errorf("create SPIFFE X509 source: %w", err)
	}
	defer source.Close()

	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return fmt.Errorf("parse SPIFFE trust domain: %w", err)
	}

	httpServer := &http.Server{
		Addr:      listen,
		Handler:   server.WorkerHandler(),
		TLSConfig: tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(td)),
	}

	log.Printf("airlock-control-plane listening on %s with SPIFFE mTLS, trust_domain=%s", listen, td)
	return httpServer.ListenAndServeTLS("", "")
}
