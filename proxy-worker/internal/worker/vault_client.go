package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func jwtSourceOptions(spiffeSocket string) []workloadapi.JWTSourceOption {
	if strings.TrimSpace(spiffeSocket) == "" {
		return nil
	}
	return []workloadapi.JWTSourceOption{workloadapi.WithClientOptions(workloadapi.WithAddr(spiffeSocket))}
}

func vaultJWTLogin(ctx context.Context, address, authMount, role, jwt string) (string, int, error) {
	endpoint, err := vaultURL(address, "/v1/auth/"+strings.Trim(authMount, "/")+"/login")
	if err != nil {
		return "", 0, err
	}
	body, err := json.Marshal(map[string]string{"jwt": jwt, "role": role})
	if err != nil {
		return "", 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("Vault JWT login failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("Vault JWT login failed HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var decoded struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return "", 0, err
	}
	if decoded.Auth.ClientToken == "" {
		return "", 0, fmt.Errorf("Vault JWT login response missing client_token")
	}
	return decoded.Auth.ClientToken, decoded.Auth.LeaseDuration, nil
}

func vaultReadKV2(ctx context.Context, address, token string, key vaultSecretKey) (string, error) {
	endpoint, err := vaultURL(address, "/v1/"+strings.Trim(key.Mount, "/")+"/data/"+strings.TrimLeft(key.Path, "/"))
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("read Vault secret %s/%s key %s: %w", key.Mount, key.Path, key.Key, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("read Vault secret %s/%s key %s failed HTTP %d: %s", key.Mount, key.Path, key.Key, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var decoded struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return "", err
	}
	raw, ok := decoded.Data.Data[key.Key]
	if !ok {
		return "", fmt.Errorf("Vault secret %s/%s missing key %s", key.Mount, key.Path, key.Key)
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("Vault secret %s/%s key %s must be a string", key.Mount, key.Path, key.Key)
	}
	return value, nil
}

func vaultURL(address, path string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(address, "/"))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("Vault address must include scheme and host")
	}
	parsed.Path = path
	return parsed.String(), nil
}
