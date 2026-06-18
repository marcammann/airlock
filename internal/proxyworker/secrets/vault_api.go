package secrets

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/marcammann/airlock/internal/vaultpath"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type vaultJWTAuthMethod struct {
	authMount string
	role      string
	jwt       string
}

func jwtSourceOptions(spiffeSocket string) []workloadapi.JWTSourceOption {
	if strings.TrimSpace(spiffeSocket) == "" {
		return nil
	}
	return []workloadapi.JWTSourceOption{workloadapi.WithClientOptions(workloadapi.WithAddr(spiffeSocket))}
}

func vaultJWTLogin(ctx context.Context, address, authMount, role, jwt string) (string, int, error) {
	client, err := newVaultAPIClient(address)
	if err != nil {
		return "", 0, err
	}
	secret, err := client.Auth().Login(ctx, vaultJWTAuthMethod{
		authMount: authMount,
		role:      role,
		jwt:       jwt,
	})
	if err != nil {
		return "", 0, fmt.Errorf("vault JWT login failed: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return "", 0, fmt.Errorf("vault JWT login response missing client_token")
	}
	return secret.Auth.ClientToken, secret.Auth.LeaseDuration, nil
}

func (m vaultJWTAuthMethod) Login(ctx context.Context, client *vaultapi.Client) (*vaultapi.Secret, error) {
	mount := strings.Trim(strings.TrimSpace(m.authMount), "/")
	if mount == "" {
		return nil, fmt.Errorf("vault JWT auth mount is required")
	}
	return client.Logical().WriteWithContext(ctx, "auth/"+mount+"/login", map[string]any{
		"jwt":  m.jwt,
		"role": m.role,
	})
}

func vaultReadKV2(ctx context.Context, address, token string, key vaultSecretKey) (string, error) {
	mount, secretPath, err := vaultpath.CleanKV2SecretPath(key.Mount, key.Path)
	if err != nil {
		return "", err
	}
	client, err := newVaultAPIClient(address)
	if err != nil {
		return "", err
	}
	client.SetToken(token)
	secret, err := client.KVv2(mount).Get(ctx, secretPath)
	if err != nil {
		var responseErr *vaultapi.ResponseError
		if errors.As(err, &responseErr) {
			return "", fmt.Errorf("read Vault secret failed with status %d", responseErr.StatusCode)
		}
		return "", fmt.Errorf("read Vault secret failed")
	}
	if secret == nil {
		return "", fmt.Errorf("vault secret was not found")
	}
	raw, ok := secret.Data[key.Key]
	if !ok {
		return "", fmt.Errorf("vault secret missing requested key")
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("vault secret value must be a string")
	}
	return value, nil
}

func newVaultAPIClient(address string) (*vaultapi.Client, error) {
	config := vaultapi.DefaultConfig()
	config.Address = strings.TrimRight(strings.TrimSpace(address), "/")
	config.HttpClient = &http.Client{Timeout: 10 * time.Second}
	if config.Address == "" {
		return nil, fmt.Errorf("vault address is required")
	}
	return vaultapi.NewClient(config)
}
