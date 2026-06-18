package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// VaultSecretProvider resolves Vault secrets cached with a SPIFFE-authenticated token.
type VaultSecretProvider struct {
	cache           map[vaultSecretKey]cachedSecret
	local           SecretProvider
	refresh         vaultRefreshFunc
	refreshInterval time.Duration
	mu              sync.Mutex
}

type vaultRefreshFunc func(context.Context) (map[vaultSecretKey]string, time.Duration, error)

type vaultSecretKey struct {
	Mount string
	Path  string
	Key   string
}

type cachedSecret struct {
	Value     string
	ExpiresAt time.Time
}

// NewVaultSecretProvider creates a Vault-backed provider for policy Vault references.
func NewVaultSecretProvider(ctx context.Context, policy CompiledPolicy, spiffeSocket string, local SecretProvider) (*VaultSecretProvider, error) {
	if policy.SecretProvider == nil || policy.SecretProvider.Vault == nil {
		return nil, fmt.Errorf("compiled policy contains Vault secret refs but no Vault secret provider config")
	}
	if local == nil {
		local = NewEnvFileSecretProvider(EnvFileSecretProviderOptions{})
	}
	settings := policy.SecretProvider.Vault
	refs := vaultSecretRefs(policy)
	if len(refs) == 0 {
		return &VaultSecretProvider{cache: map[vaultSecretKey]cachedSecret{}, local: local}, nil
	}

	workloadID, err := spiffeid.FromString(policy.Workload.SPIFFEID)
	if err != nil {
		return nil, fmt.Errorf("parse workload SPIFFE ID: %w", err)
	}
	slog.Info("airlock-proxy-worker requesting Vault JWT-SVID", "workload", workloadID.String())
	jwtSource, err := workloadapi.NewJWTSource(ctx, jwtSourceOptions(spiffeSocket)...)
	if err != nil {
		return nil, fmt.Errorf("create SPIFFE JWT source: %w", err)
	}
	refresh := func(ctx context.Context) (map[vaultSecretKey]string, time.Duration, error) {
		return refreshVaultSecrets(ctx, settings, workloadID, jwtSource, refs)
	}
	values, ttl, err := refresh(ctx)
	if err != nil {
		jwtSource.Close()
		return nil, err
	}

	cache := map[vaultSecretKey]cachedSecret{}
	expiresAt := time.Now().Add(ttl)
	for key, value := range values {
		cache[key] = cachedSecret{Value: value, ExpiresAt: expiresAt}
	}
	slog.Info("airlock-proxy-worker preloaded Vault secrets", "count", len(values), "ttlSeconds", int(ttl.Seconds()))
	provider := &VaultSecretProvider{
		cache:           cache,
		local:           local,
		refresh:         refresh,
		refreshInterval: ttl / 2,
	}
	go func() {
		<-ctx.Done()
		jwtSource.Close()
	}()
	provider.startBackgroundRefresh(ctx, ttl)
	return provider, nil
}

func vaultSecretCacheTTL(leaseSeconds int) (time.Duration, error) {
	if leaseSeconds <= 0 {
		return 0, fmt.Errorf("vault JWT login returned non-positive lease_duration")
	}
	ttl := time.Duration(leaseSeconds) * time.Second
	if ttl > 5*time.Minute {
		return 5 * time.Minute, nil
	}
	return ttl, nil
}

func refreshVaultSecrets(ctx context.Context, settings *CompiledVaultProvider, workloadID spiffeid.ID, jwtSource *workloadapi.JWTSource, refs []SecretRef) (map[vaultSecretKey]string, time.Duration, error) {
	jwtSVID, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: settings.Audience,
		Subject:  workloadID,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("fetch SPIFFE JWT-SVID: %w", err)
	}
	slog.Info("airlock-proxy-worker fetched Vault JWT-SVID", "subject", workloadID.String())

	vaultToken, leaseSeconds, err := vaultJWTLogin(ctx, settings.Address, settings.AuthMount, settings.Role, jwtSVID.Marshal())
	if err != nil {
		return nil, 0, err
	}
	slog.Info("airlock-proxy-worker authenticated to Vault", "leaseDuration", leaseSeconds)
	ttl, err := vaultSecretCacheTTL(leaseSeconds)
	if err != nil {
		return nil, 0, err
	}

	values := map[vaultSecretKey]string{}
	for _, ref := range refs {
		key := vaultSecretKey{Mount: ref.Mount, Path: ref.Path, Key: ref.Key}
		value, err := vaultReadKV2(ctx, settings.Address, vaultToken, key)
		if err != nil {
			return nil, 0, err
		}
		values[key] = value
	}
	return values, ttl, nil
}

func (p *VaultSecretProvider) startBackgroundRefresh(ctx context.Context, ttl time.Duration) {
	if p.refresh == nil {
		return
	}
	interval := p.refreshInterval
	if interval <= 0 {
		interval = ttl / 2
	}
	if interval <= 0 {
		return
	}
	go func() {
		timer := time.NewTimer(interval)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				p.refreshCachedSecrets(ctx)
				timer.Reset(interval)
			}
		}
	}()
}

func (p *VaultSecretProvider) refreshCachedSecrets(ctx context.Context) {
	values, ttl, err := p.refresh(ctx)
	if err != nil {
		slog.Error("airlock-proxy-worker Vault refresh failed")
		return
	}
	expiresAt := time.Now().Add(ttl)
	p.mu.Lock()
	if p.cache == nil {
		p.cache = map[vaultSecretKey]cachedSecret{}
	}
	for key, value := range values {
		p.cache[key] = cachedSecret{Value: value, ExpiresAt: expiresAt}
	}
	p.mu.Unlock()
}

// Resolve returns a cached Vault secret or delegates non-Vault refs to the local provider.
func (p *VaultSecretProvider) Resolve(ref SecretRef) (string, error) {
	if ref.Provider != "vault" {
		if p.local == nil {
			p.local = NewEnvFileSecretProvider(EnvFileSecretProviderOptions{})
		}
		return p.local.Resolve(ref)
	}
	key := vaultSecretKey{Mount: ref.Mount, Path: ref.Path, Key: ref.Key}
	p.mu.Lock()
	defer p.mu.Unlock()
	secret, ok := p.cache[key]
	if !ok {
		err := fmt.Errorf("vault secret was not preloaded")
		observeSecretResolve("vault", err)
		return "", err
	}
	if time.Now().After(secret.ExpiresAt) {
		err := fmt.Errorf("vault secret cache entry expired")
		observeSecretResolve("vault", err)
		return "", err
	}
	observeSecretResolve("vault", nil)
	return secret.Value, nil
}
