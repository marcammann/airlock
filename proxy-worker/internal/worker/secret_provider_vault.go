package worker

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type VaultSecretProvider struct {
	cache map[vaultSecretKey]cachedSecret
	mu    sync.Mutex
}

type vaultSecretKey struct {
	Mount string
	Path  string
	Key   string
}

type cachedSecret struct {
	Value     string
	ExpiresAt time.Time
}

func NewVaultSecretProvider(ctx context.Context, policy CompiledPolicy, spiffeSocket string) (*VaultSecretProvider, error) {
	if policy.SecretProvider == nil || policy.SecretProvider.Vault == nil {
		return nil, fmt.Errorf("compiled policy contains Vault secret refs but no Vault secret provider config")
	}
	settings := policy.SecretProvider.Vault
	refs := vaultSecretRefs(policy)
	if len(refs) == 0 {
		return &VaultSecretProvider{cache: map[vaultSecretKey]cachedSecret{}}, nil
	}

	workloadID, err := spiffeid.FromString(policy.Workload.SPIFFEID)
	if err != nil {
		return nil, fmt.Errorf("parse workload SPIFFE ID: %w", err)
	}
	fmt.Fprintf(os.Stderr, "airlock-proxy-worker vault: requesting jwt-svid workload=%s audience=%s vault_addr=%s auth_mount=%s role=%s\n", workloadID, settings.Audience, settings.Address, settings.AuthMount, settings.Role)
	jwtSource, err := workloadapi.NewJWTSource(ctx, jwtSourceOptions(spiffeSocket)...)
	if err != nil {
		return nil, fmt.Errorf("create SPIFFE JWT source: %w", err)
	}
	defer jwtSource.Close()
	jwtSVID, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: settings.Audience,
		Subject:  workloadID,
	})
	if err != nil {
		return nil, fmt.Errorf("fetch SPIFFE JWT-SVID: %w", err)
	}
	fmt.Fprintf(os.Stderr, "airlock-proxy-worker vault: fetched jwt-svid subject=%s audience=%s\n", workloadID, settings.Audience)

	vaultToken, leaseSeconds, err := vaultJWTLogin(ctx, settings.Address, settings.AuthMount, settings.Role, jwtSVID.Marshal())
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "airlock-proxy-worker vault: authenticated role=%s lease_duration=%d\n", settings.Role, leaseSeconds)
	ttl, err := vaultSecretCacheTTL(leaseSeconds)
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(ttl)

	cache := map[vaultSecretKey]cachedSecret{}
	for _, ref := range refs {
		key := vaultSecretKey{Mount: ref.Mount, Path: ref.Path, Key: ref.Key}
		value, err := vaultReadKV2(ctx, settings.Address, vaultToken, key)
		if err != nil {
			return nil, err
		}
		cache[key] = cachedSecret{Value: value, ExpiresAt: expiresAt}
		fmt.Fprintf(os.Stderr, "airlock-proxy-worker vault: preloaded secret mount=%s path=%s key=%s ttl_seconds=%d\n", key.Mount, key.Path, key.Key, int(ttl.Seconds()))
	}
	return &VaultSecretProvider{cache: cache}, nil
}

func vaultSecretCacheTTL(leaseSeconds int) (time.Duration, error) {
	if leaseSeconds <= 0 {
		return 0, fmt.Errorf("Vault JWT login returned non-positive lease_duration")
	}
	ttl := time.Duration(leaseSeconds) * time.Second
	if ttl > 5*time.Minute {
		return 5 * time.Minute, nil
	}
	return ttl, nil
}

func (p *VaultSecretProvider) Resolve(ref SecretRef) (string, error) {
	if ref.Provider != "vault" {
		return EnvFileSecretProvider{}.Resolve(ref)
	}
	key := vaultSecretKey{Mount: ref.Mount, Path: ref.Path, Key: ref.Key}
	p.mu.Lock()
	defer p.mu.Unlock()
	secret, ok := p.cache[key]
	if !ok {
		return "", fmt.Errorf("Vault secret %s/%s key %s was not preloaded", key.Mount, key.Path, key.Key)
	}
	if time.Now().After(secret.ExpiresAt) {
		return "", fmt.Errorf("Vault secret %s/%s key %s cache entry expired", key.Mount, key.Path, key.Key)
	}
	return secret.Value, nil
}
