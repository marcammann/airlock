package controlplane

import (
	"context"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	airlockv1 "github.com/marcammann/airlock/api/v1alpha1"
	"github.com/marcammann/airlock/internal/controlplane"
	"github.com/marcammann/airlock/internal/policy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestLoadControlPlaneEnvParsesTypedValues(t *testing.T) {
	t.Setenv("AIRLOCK_LISTEN", "127.0.0.1:18080")
	t.Setenv("AIRLOCK_EVENT_LOG_LIMIT", "42")
	t.Setenv("AIRLOCK_EVENT_LOG_TTL", "15m")
	t.Setenv("AIRLOCK_EVENT_INGEST_RATE", "12.5")
	t.Setenv("AIRLOCK_INSECURE", "true")
	t.Setenv("AIRLOCK_KUBE_LEADER_ELECTION", "false")
	t.Setenv("AIRLOCK_KUBE_NAMESPACE", "")
	t.Setenv("POD_NAMESPACE", "pod-ns")
	t.Setenv("AIRLOCK_SPIFFE_SOCKET", "")
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/spire.sock")

	config, err := loadControlPlaneEnv()
	if err != nil {
		t.Fatal(err)
	}
	if config.Listen != "127.0.0.1:18080" {
		t.Fatalf("Listen = %q, want custom listen", config.Listen)
	}
	if config.EventLogLimit != 42 {
		t.Fatalf("EventLogLimit = %d, want 42", config.EventLogLimit)
	}
	if config.EventLogTTL != 15*time.Minute {
		t.Fatalf("EventLogTTL = %s, want 15m", config.EventLogTTL)
	}
	if config.EventIngestRate != 12.5 {
		t.Fatalf("EventIngestRate = %f, want 12.5", config.EventIngestRate)
	}
	if !config.Insecure {
		t.Fatal("Insecure = false, want true")
	}
	if config.KubeLeaderElection {
		t.Fatal("KubeLeaderElection = true, want false")
	}
	if config.KubeNamespace != "pod-ns" {
		t.Fatalf("KubeNamespace = %q, want pod-ns", config.KubeNamespace)
	}
	if config.SPIFFESocket != "unix:///tmp/spire.sock" {
		t.Fatalf("SPIFFESocket = %q, want external SPIFFE endpoint socket", config.SPIFFESocket)
	}
}

func TestLoadControlPlaneEnvRejectsInvalidTypedValue(t *testing.T) {
	t.Setenv("AIRLOCK_EVENT_LOG_LIMIT", "nope")

	if _, err := loadControlPlaneEnv(); err == nil {
		t.Fatal("loadControlPlaneEnv() error = nil, want invalid int error")
	}
}

func TestParseControlPlaneFlagsMergesEnvListsAndTracksExplicitAuth(t *testing.T) {
	t.Setenv("AIRLOCK_POLICY_PATHS", "env-policy-a.yaml, env-policy-b.yaml")
	t.Setenv("AIRLOCK_WORKLOAD_PATHS", "env-workload.yaml")
	t.Setenv("AIRLOCK_SECRET_PROVIDER_CONFIG_PATHS", "env-secret-provider.yaml")
	t.Setenv("AIRLOCK_ADMIN_RBAC_BINDINGS", "group:dev=viewer;user:admin@example.test=admin")
	restoreFlags := replaceCommandLine(t, []string{
		"airlock-control-plane",
		"--policy", "flag-policy.yaml",
		"--workload", "flag-workload.yaml",
		"--worker-auth", "none",
	})
	defer restoreFlags()

	config, state := parseControlPlaneFlags(controlPlaneEnv{WorkerAuth: "spiffe", AdminAuth: "spiffe"})

	if got, want := strings.Join(config.PolicyPaths, ","), "flag-policy.yaml,env-policy-a.yaml,env-policy-b.yaml"; got != want {
		t.Fatalf("PolicyPaths = %q, want %q", got, want)
	}
	if got, want := strings.Join(config.WorkloadPaths, ","), "flag-workload.yaml,env-workload.yaml"; got != want {
		t.Fatalf("WorkloadPaths = %q, want %q", got, want)
	}
	if got, want := strings.Join(config.SecretProviderConfigPaths, ","), "env-secret-provider.yaml"; got != want {
		t.Fatalf("SecretProviderConfigPaths = %q, want %q", got, want)
	}
	if got, want := strings.Join(config.AdminRBACBindings, ","), "group:dev=viewer,user:admin@example.test=admin"; got != want {
		t.Fatalf("AdminRBACBindings = %q, want %q", got, want)
	}
	if !state.WorkerAuthExplicit {
		t.Fatal("WorkerAuthExplicit = false, want true")
	}
	if state.AdminAuthExplicit {
		t.Fatal("AdminAuthExplicit = true, want false")
	}
}

func TestValidateAuthConfigRequiresExplicitInsecure(t *testing.T) {
	tests := []struct {
		name     string
		mode     controlplane.AuthMode
		surface  string
		insecure bool
		wantErr  string
	}{
		{name: "spiffe worker", mode: controlplane.AuthModeSPIFFE, surface: "worker"},
		{name: "oidc admin", mode: controlplane.AuthModeOIDC, surface: "admin"},
		{name: "oidc worker", mode: controlplane.AuthModeOIDC, surface: "worker", wantErr: "worker auth mode oidc is not supported"},
		{name: "none without insecure", mode: controlplane.AuthModeNone, surface: "worker", wantErr: "--insecure"},
		{name: "none with insecure", mode: controlplane.AuthModeNone, surface: "worker", insecure: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuthConfig(tt.mode, tt.surface, tt.insecure)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateAuthConfig() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateAuthConfig() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func replaceCommandLine(t *testing.T, args []string) func() {
	t.Helper()
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = args
	return func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	}
}

func TestAdminListenerRequiresTLSWithoutInsecure(t *testing.T) {
	tests := []struct {
		name     string
		listen   string
		cert     string
		key      string
		insecure bool
		wantErr  string
	}{
		{name: "disabled"},
		{name: "tls configured", listen: "127.0.0.1:8443", cert: "admin.crt", key: "admin.key"},
		{name: "plain insecure", listen: "127.0.0.1:8081", insecure: true},
		{name: "plain secure denied", listen: "127.0.0.1:8081", wantErr: "--admin-tls-cert"},
		{name: "partial tls denied", listen: "127.0.0.1:8081", cert: "admin.crt", wantErr: "must be set together"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAdminTLSConfig(tt.listen, tt.cert, tt.key, tt.insecure)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateAdminTLSConfig() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateAdminTLSConfig() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestPatchKubernetesStatusesUsesControllerRuntimeClient(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := airlockv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	workload := &policy.AirlockWorkload{
		TypeMeta: metav1.TypeMeta{APIVersion: policy.APIVersion, Kind: "AirlockWorkload"},
		Metadata: policy.Metadata{
			Name:       "code-agent",
			Namespace:  "airlock-system",
			Generation: 7,
		},
	}
	kube := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&policy.AirlockWorkload{}).
		WithObjects(workload).
		Build()

	controlplane.PatchKubernetesStatusesWithClient(context.Background(), kube, []controlplane.KubernetesPolicyStatusUpdate{{
		Workload: *workload,
		Status: policy.Status{
			ObservedGeneration: workload.Metadata.Generation,
			PolicyHash:         "sha256:test",
			Conditions:         []policy.StatusCondition{{Type: "Ready"}},
		},
	}}, true, true)

	var out policy.AirlockWorkload
	if err := kube.Get(context.Background(), ctrlclient.ObjectKey{Namespace: "airlock-system", Name: "code-agent"}, &out); err != nil {
		t.Fatal(err)
	}
	if got, want := out.Status.PolicyHash, "sha256:test"; got != want {
		t.Fatalf("policyHash = %q, want %q", got, want)
	}
	if len(out.Status.Conditions) != 1 || out.Status.Conditions[0].Status != "True" || out.Status.Conditions[0].Reason != "Reconciled" {
		t.Fatalf("conditions = %+v, want Ready=True Reconciled", out.Status.Conditions)
	}
}

func TestKubernetesManagerOptionsAreScopedAndLeaderElected(t *testing.T) {
	assertLeaderElectionManagerOptions(t)
}

func TestLeaderElection(t *testing.T) {
	assertLeaderElectionManagerOptions(t)
}

func assertLeaderElectionManagerOptions(t *testing.T) {
	t.Helper()
	scheme, err := newKubernetesScheme()
	if err != nil {
		t.Fatal(err)
	}
	options := newKubernetesManagerOptions(scheme, "airlock-system", true, 30*time.Second, nil)

	if options.Scheme != scheme {
		t.Fatal("manager options did not use provided scheme")
	}
	if !options.LeaderElection {
		t.Fatal("LeaderElection = false, want true")
	}
	if got, want := options.LeaderElectionNamespace, "airlock-system"; got != want {
		t.Fatalf("LeaderElectionNamespace = %q, want %q", got, want)
	}
	if got, want := options.LeaderElectionID, "airlock-control-plane.airlock.dev"; got != want {
		t.Fatalf("LeaderElectionID = %q, want %q", got, want)
	}
	if options.Metrics.BindAddress != "0" {
		t.Fatalf("Metrics.BindAddress = %q, want disabled", options.Metrics.BindAddress)
	}
	if options.HealthProbeBindAddress != "0" {
		t.Fatalf("HealthProbeBindAddress = %q, want disabled", options.HealthProbeBindAddress)
	}
	if _, ok := options.Cache.DefaultNamespaces["airlock-system"]; !ok {
		t.Fatalf("DefaultNamespaces = %+v, want airlock-system scoped cache", options.Cache.DefaultNamespaces)
	}
	if options.Cache.SyncPeriod == nil || *options.Cache.SyncPeriod != 30*time.Second {
		t.Fatalf("SyncPeriod = %v, want 30s", options.Cache.SyncPeriod)
	}
}

func TestKubernetesWebhookListenAddressParsing(t *testing.T) {
	host, port, err := splitKubernetesWebhookListenAddress("127.0.0.1:9443")
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" || port != 9443 {
		t.Fatalf("host, port = %q, %d; want 127.0.0.1, 9443", host, port)
	}

	host, port, err = splitKubernetesWebhookListenAddress(":9443")
	if err != nil {
		t.Fatal(err)
	}
	if host != "" || port != 9443 {
		t.Fatalf("host, port = %q, %d; want empty host, 9443", host, port)
	}
}

func TestWebhookListenRequiresKubeSource(t *testing.T) {
	_, err := validateControlPlaneRuntimeConfig(controlPlaneConfig{
		controlPlaneEnv: controlPlaneEnv{
			WebhookListen:            ":9443",
			HeartbeatStaleThreshold:  9,
			EventLog:                 string(controlplane.EventLogMemory),
			EventLogLimit:            1000,
			EventLogTTL:              time.Hour,
			EventIngestRate:          100,
			EventIngestBurst:         500,
			EventIngestRatePerProxy:  2,
			EventIngestBurstPerProxy: 50,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "--kube-source") {
		t.Fatalf("validateControlPlaneRuntimeConfig() error = %v, want kube-source requirement", err)
	}
}

func TestControlPlaneGracefulShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	})
	server := newHTTPServer(listener.Addr().String(), handler)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runHTTPServers(ctx, []namedHTTPServer{{
			Name:   "test",
			Addr:   listener.Addr().String(),
			Server: server,
			Serve:  func() error { return server.Serve(listener) },
		}})
	}()

	responseBody := make(chan string, 1)
	requestErr := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + listener.Addr().String())
		if err != nil {
			requestErr <- err
			return
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			requestErr <- err
			return
		}
		if err := resp.Body.Close(); err != nil {
			requestErr <- err
			return
		}
		responseBody <- string(body)
	}()
	<-started
	cancel()
	select {
	case err := <-requestErr:
		t.Fatal(err)
	case body := <-responseBody:
		if body != "ok" {
			t.Fatalf("body = %q, want ok", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request did not complete")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runHTTPServers() error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("control-plane server did not stop after context cancellation")
	}
}
