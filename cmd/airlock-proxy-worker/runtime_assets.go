package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/marcammann/airlock/internal/proxyworker/builtin"
	"github.com/marcammann/airlock/internal/proxyworker/egress"
	workersecrets "github.com/marcammann/airlock/internal/proxyworker/secrets"
)

type proxyTLSAssets struct {
	MITMCA            *builtin.CertificateAuthority
	UpstreamTLSConfig *tls.Config
}

func buildReloadableSecrets(ctx context.Context, policy egress.CompiledPolicy, spiffeSocket string, secretFileRoot string) (*workersecrets.ReloadableSecretProvider, error) {
	secrets, err := workersecrets.NewSecretProviderForPolicy(ctx, policy, spiffeSocket, workersecrets.SecretProviderOptions{
		SecretFileRoot: secretFileRoot,
	})
	if err != nil {
		return nil, err
	}
	return workersecrets.NewReloadableSecretProvider(secrets), nil
}

func loadProxyTLSAssets(mitmCACert string, mitmCAKey string, upstreamCACert string) (proxyTLSAssets, error) {
	var assets proxyTLSAssets
	if mitmCACert != "" || mitmCAKey != "" {
		if mitmCACert == "" || mitmCAKey == "" {
			return proxyTLSAssets{}, fmt.Errorf("--mitm-ca-cert and --mitm-ca-key must be set together")
		}
		ca, err := builtin.LoadCertificateAuthority(mitmCACert, mitmCAKey)
		if err != nil {
			return proxyTLSAssets{}, err
		}
		assets.MITMCA = ca
	}
	if upstreamCACert != "" {
		tlsConfig, err := builtin.LoadTLSClientConfigWithRootCAs(upstreamCACert)
		if err != nil {
			return proxyTLSAssets{}, err
		}
		assets.UpstreamTLSConfig = tlsConfig
	}
	return assets, nil
}
