package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	airlockv1 "github.com/marcammann/airlock/api/v1alpha1"
)

const testWorkloadIdentity = "spiffe://airlock.local/ns/demo/sa/code-agent/component/airlock-proxy-worker"

func TestVaultSecretProviderResolveFailsWhenCacheEntryExpired(t *testing.T) {
	key := vaultSecretKey{Mount: "secret", Path: "airlock/openai/code-agent", Key: "api_key"}
	provider := &VaultSecretProvider{
		cache: map[vaultSecretKey]cachedSecret{
			key: {Value: "expired-token", ExpiresAt: time.Now().Add(-time.Second)},
		},
	}

	_, err := provider.Resolve(SecretRef{
		Provider: "vault",
		Mount:    key.Mount,
		Engine:   "kv-v2",
		Path:     key.Path,
		Key:      key.Key,
	})
	if err == nil {
		t.Fatal("Resolve() error = nil, want expired cache error")
	}
	if !strings.Contains(err.Error(), "cache entry expired") {
		t.Fatalf("error = %q, want cache entry expired", err)
	}
}

func TestVaultSecretCacheTTLTracksVaultTokenLease(t *testing.T) {
	ttl, err := vaultSecretCacheTTL(2)
	if err != nil {
		t.Fatal(err)
	}
	if ttl != 2*time.Second {
		t.Fatalf("ttl = %s, want Vault token lease", ttl)
	}

	ttl, err = vaultSecretCacheTTL(20 * 60)
	if err != nil {
		t.Fatal(err)
	}
	if ttl != 5*time.Minute {
		t.Fatalf("ttl = %s, want worker cache cap", ttl)
	}
}

func TestVaultSecretCacheTTLRejectsUnknownTokenLease(t *testing.T) {
	_, err := vaultSecretCacheTTL(0)
	if err == nil {
		t.Fatal("vaultSecretCacheTTL() error = nil, want non-positive lease failure")
	}
	if !strings.Contains(err.Error(), "non-positive lease_duration") {
		t.Fatalf("error = %q, want non-positive lease_duration", err)
	}
}

func TestVaultProviderRefreshesBeforeExpiry(t *testing.T) {
	key := vaultSecretKey{Mount: "secret", Path: "airlock/openai/code-agent", Key: "api_key"}
	refreshed := make(chan struct{}, 1)
	provider := &VaultSecretProvider{
		cache: map[vaultSecretKey]cachedSecret{
			key: {Value: "old-token", ExpiresAt: time.Now().Add(time.Hour)},
		},
		refreshInterval: 5 * time.Millisecond,
		refresh: func(context.Context) (map[vaultSecretKey]string, time.Duration, error) {
			select {
			case refreshed <- struct{}{}:
			default:
			}
			return map[vaultSecretKey]string{key: "new-token"}, time.Hour, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	provider.startBackgroundRefresh(ctx, time.Hour)

	select {
	case <-refreshed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for Vault refresh")
	}
	deadline := time.After(500 * time.Millisecond)
	for {
		value, err := provider.Resolve(SecretRef{Provider: "vault", Mount: key.Mount, Engine: "kv-v2", Path: key.Path, Key: key.Key})
		if err != nil {
			t.Fatal(err)
		}
		if value == "new-token" {
			cancel()
			return
		}
		select {
		case <-deadline:
			t.Fatalf("value = %q, want refreshed token", value)
		case <-time.After(time.Millisecond):
		}
	}
}

func TestVaultProviderFailsClosedAfterTTL(t *testing.T) {
	key := vaultSecretKey{Mount: "secret", Path: "airlock/openai/code-agent", Key: "api_key"}
	provider := &VaultSecretProvider{
		cache: map[vaultSecretKey]cachedSecret{
			key: {Value: "old-token", ExpiresAt: time.Now().Add(40 * time.Millisecond)},
		},
		refreshInterval: 5 * time.Millisecond,
		refresh: func(context.Context) (map[vaultSecretKey]string, time.Duration, error) {
			return nil, 0, errors.New("vault unavailable")
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	provider.startBackgroundRefresh(ctx, 10*time.Millisecond)

	value, err := provider.Resolve(SecretRef{Provider: "vault", Mount: key.Mount, Engine: "kv-v2", Path: key.Path, Key: key.Key})
	if err != nil {
		t.Fatal(err)
	}
	if value != "old-token" {
		t.Fatalf("value = %q, want old token before expiry", value)
	}

	deadline := time.After(500 * time.Millisecond)
	for {
		_, err := provider.Resolve(SecretRef{Provider: "vault", Mount: key.Mount, Engine: "kv-v2", Path: key.Path, Key: key.Key})
		if err != nil {
			if !strings.Contains(err.Error(), "cache entry expired") {
				t.Fatalf("error = %q, want cache expiry", err)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for Vault cache expiry")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestVaultProviderDoesNotLogSecretPath(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	key := vaultSecretKey{Mount: "secret", Path: "airlock/openai/code-agent", Key: "api_key"}
	provider := &VaultSecretProvider{
		cache: map[vaultSecretKey]cachedSecret{
			key: {Value: "old-token", ExpiresAt: time.Now().Add(time.Hour)},
		},
		refresh: func(context.Context) (map[vaultSecretKey]string, time.Duration, error) {
			return nil, 0, fmt.Errorf("read Vault secret %s/%s key %s: vault unavailable", key.Mount, key.Path, key.Key)
		},
	}

	provider.refreshCachedSecrets(context.Background())

	output := logs.String()
	if !strings.Contains(output, "Vault refresh failed") {
		t.Fatalf("logs = %q, want Vault refresh failure", output)
	}
	for _, leaked := range []string{key.Mount, key.Path, key.Key, "vault unavailable"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("logs leaked Vault secret metadata %q: %q", leaked, output)
		}
	}
}

func TestVaultReadKV2Non200FailsClosed(t *testing.T) {
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "vault unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(vault.Close)

	_, err := vaultReadKV2(context.Background(), vault.URL, "vault-token", vaultSecretKey{
		Mount: "secret",
		Path:  "airlock/openai/code-agent",
		Key:   "api_key",
	})
	if err == nil {
		t.Fatal("vaultReadKV2() error = nil, want non-200 error")
	}
	if !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("error = %q, want Vault status 503", err)
	}
	if strings.Contains(err.Error(), "airlock/openai/code-agent") || strings.Contains(err.Error(), "api_key") {
		t.Fatalf("error leaked Vault secret metadata: %q", err)
	}
}

func TestVaultRejectsTraversalPath(t *testing.T) {
	requests := make(chan struct{}, 1)
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests <- struct{}{}
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	t.Cleanup(vault.Close)

	for _, secretPath := range []string{
		"../../sys/raw/secret",
		"auth/foo",
		"foo/../bar",
	} {
		t.Run(secretPath, func(t *testing.T) {
			_, err := vaultReadKV2(context.Background(), vault.URL, "vault-token", vaultSecretKey{
				Mount: "secret",
				Path:  secretPath,
				Key:   "api_key",
			})
			if err == nil {
				t.Fatal("vaultReadKV2() error = nil, want unsafe path error")
			}
			if !strings.Contains(err.Error(), "unsafe Vault secret path") {
				t.Fatalf("error = %q, want unsafe path", err)
			}
			select {
			case <-requests:
				t.Fatal("Vault received request for unsafe path")
			default:
			}
		})
	}
}

func TestSPIFFEVaultAuthFailsBeforeVaultRequestWhenWorkloadAPIMissing(t *testing.T) {
	vaultRequests := make(chan struct{}, 1)
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		vaultRequests <- struct{}{}
		http.Error(w, "unexpected vault request", http.StatusInternalServerError)
	}))
	t.Cleanup(vault.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	t.Cleanup(cancel)
	missingSocket := "unix://" + filepath.Join(t.TempDir(), "missing-spire-agent.sock")

	_, err := NewVaultSecretProvider(ctx, testVaultPolicy(vault.URL), missingSocket, nil)
	if err == nil {
		t.Fatal("NewVaultSecretProvider() error = nil, want missing workload API error")
	}
	if !strings.Contains(err.Error(), "SPIFFE") {
		t.Fatalf("error = %q, want SPIFFE workload API failure", err)
	}
	select {
	case <-vaultRequests:
		t.Fatal("Vault received request despite missing workload API")
	default:
	}
}

func testVaultPolicy(vaultAddress string) CompiledPolicy {
	policy := CompiledPolicy{
		Version:    airlockv1.APIVersion,
		PolicyName: "test-policy",
		Workload: airlockv1.WorkloadIdentity{
			SPIFFEID:       testWorkloadIdentity,
			Namespace:      "demo",
			ServiceAccount: "code-agent",
		},
		Egress: []airlockv1.EgressRule{{
			Name:   "local-upstream",
			Scheme: "http",
			Host:   "api.example.test",
			Port:   80,
			Rewrites: []airlockv1.RewriteRule{{
				Target:        "header",
				Name:          "Authorization",
				ValueTemplate: "Bearer {{secret}}",
				ValueFrom: airlockv1.SecretRef{
					Provider: "env",
					Name:     "test-token",
					Env:      "AIRLOCK_TEST_TOKEN",
				},
			}},
		}},
	}
	policy.SecretProvider = &airlockv1.CompiledSecretProvider{
		Provider: "vault",
		Vault: &airlockv1.CompiledVaultProvider{
			Address:   vaultAddress,
			AuthMount: "jwt",
			Audience:  "vault",
			Role:      "airlock-demo-code-agent",
		},
	}
	policy.Egress[0].Rewrites[0].ValueFrom = airlockv1.SecretRef{
		Provider: "vault",
		Mount:    "secret",
		Engine:   "kv-v2",
		Path:     "airlock/openai/code-agent",
		Key:      "api_key",
	}
	return policy
}
