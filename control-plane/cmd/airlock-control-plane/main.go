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

	"github.com/marc/airlock/control-plane/internal/controlplane"
	"github.com/marc/airlock/control-plane/internal/policy"
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
	var healthListen string
	var policyPaths stringList
	var secretProviderConfigPaths stringList
	var authMode string
	var devToken string
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
	flag.StringVar(&healthListen, "health-listen", os.Getenv("AIRLOCK_HEALTH_LISTEN"), "optional separate plain HTTP health listen address")
	flag.Var(&policyPaths, "policy", "path to an AirlockPolicy YAML file; may be repeated")
	flag.Var(&secretProviderConfigPaths, "secret-provider-config", "path to a SecretProviderConfig YAML file; may be repeated")
	flag.StringVar(&authMode, "auth-mode", envOrDefault("AIRLOCK_AUTH_MODE", "none"), "policy API auth mode: none, dev-token, or spiffe")
	flag.StringVar(&devToken, "dev-token", os.Getenv("AIRLOCK_DEV_TOKEN"), "optional development bearer token")
	flag.StringVar(&spiffeSocket, "spiffe-socket", envOrDefault("SPIFFE_ENDPOINT_SOCKET", "unix:///run/spire/agent-sockets/spire-agent.sock"), "SPIFFE Workload API socket URI")
	flag.StringVar(&spiffeTrustDomain, "spiffe-trust-domain", envOrDefault("AIRLOCK_SPIFFE_TRUST_DOMAIN", "airlock.local"), "SPIFFE trust domain accepted for client SVIDs")
	flag.BoolVar(&vaultReconcile, "vault-reconcile", envBool("AIRLOCK_VAULT_RECONCILE"), "reconcile generated Vault policies and JWT roles at startup")
	flag.StringVar(&vaultAdminToken, "vault-admin-token", os.Getenv("AIRLOCK_VAULT_ADMIN_TOKEN"), "Vault admin token used only for policy/role reconciliation")
	flag.StringVar(&vaultAdminTokenFile, "vault-admin-token-file", os.Getenv("AIRLOCK_VAULT_ADMIN_TOKEN_FILE"), "file containing Vault admin token used only for policy/role reconciliation")
	flag.BoolVar(&kubeSource, "kube-source", envBool("AIRLOCK_KUBE_SOURCE"), "load AirlockPolicy and SecretProviderConfig objects from the Kubernetes API")
	flag.StringVar(&kubeNamespace, "kube-namespace", envOrDefault("AIRLOCK_KUBE_NAMESPACE", envOrDefault("POD_NAMESPACE", "airlock-system")), "namespace containing AirlockPolicy and SecretProviderConfig objects")
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
	if envPaths := strings.TrimSpace(os.Getenv("AIRLOCK_SECRET_PROVIDER_CONFIG_PATHS")); envPaths != "" {
		for _, path := range strings.Split(envPaths, ",") {
			if path = strings.TrimSpace(path); path != "" {
				secretProviderConfigPaths = append(secretProviderConfigPaths, path)
			}
		}
	}

	if !kubeSource && len(policyPaths) == 0 {
		return fmt.Errorf("at least one --policy or AIRLOCK_POLICY_PATHS entry is required")
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
		store, err = controlplane.LoadPolicyStoreWithSecretProviderConfigs(policyPaths, secretProviderConfigPaths)
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

	mode := controlplane.AuthMode(authMode)
	server := controlplane.NewServerWithAuth(store, mode, devToken, os.Stderr)
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

	switch mode {
	case controlplane.AuthModeNone, controlplane.AuthModeDevToken:
		log.Printf("airlock-control-plane listening on %s with %d policy mapping(s), auth_mode=%s", listen, store.Len(), mode)
		return http.ListenAndServe(listen, server.Handler())
	case controlplane.AuthModeSPIFFE:
		return serveSPIFFE(listen, spiffeSocket, spiffeTrustDomain, server)
	default:
		return fmt.Errorf("unsupported auth mode %q", authMode)
	}
}

func envOrDefault(name string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
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
		if err := controlplane.PatchAirlockPolicyStatus(ctx, opts, update.Policy, status); err != nil {
			log.Printf("patch AirlockPolicy status %s/%s: %v", update.Policy.Metadata.Namespace, update.Policy.Metadata.Name, err)
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
		Handler:   server.Handler(),
		TLSConfig: tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(td)),
	}

	log.Printf("airlock-control-plane listening on %s with SPIFFE mTLS, trust_domain=%s", listen, td)
	return httpServer.ListenAndServeTLS("", "")
}
