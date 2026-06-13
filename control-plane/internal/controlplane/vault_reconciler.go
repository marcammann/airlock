package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marc/airlock/control-plane/internal/policy"
)

type VaultReconcileOptions struct {
	AdminToken string
	HTTPClient *http.Client
	Audit      io.Writer
}

type VaultReconcileResult struct {
	Policies int
	Roles    int
}

type vaultClient struct {
	address string
	token   string
	client  *http.Client
}

func ReconcileVault(ctx context.Context, store *PolicyStore, opts VaultReconcileOptions) (VaultReconcileResult, error) {
	if store == nil {
		return VaultReconcileResult{}, fmt.Errorf("policy store is nil")
	}
	if strings.TrimSpace(opts.AdminToken) == "" {
		return VaultReconcileResult{}, fmt.Errorf("vault admin token is required")
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if opts.Audit == nil {
		opts.Audit = io.Discard
	}

	var result VaultReconcileResult
	for _, compiled := range store.Policies() {
		if compiled.SecretProvider == nil || compiled.SecretProvider.Vault == nil {
			continue
		}
		vault := compiled.SecretProvider.Vault
		client := vaultClient{
			address: vault.Address,
			token:   opts.AdminToken,
			client:  opts.HTTPClient,
		}

		policyName := vaultPolicyName(compiled)
		acl, err := vaultACLPolicy(compiled)
		if err != nil {
			return result, fmt.Errorf("build Vault ACL policy for %q: %w", compiled.PolicyName, err)
		}
		if err := client.writeACLPolicy(ctx, policyName, acl); err != nil {
			return result, fmt.Errorf("write Vault ACL policy %q: %w", policyName, err)
		}
		result.Policies++

		role := vaultRole{
			RoleType:       "jwt",
			UserClaim:      "sub",
			BoundAudiences: []string{vault.Audience},
			BoundSubject:   compiled.Workload.SPIFFEID,
			TokenTTL:       "15m",
			TokenPolicies:  []string{policyName},
		}
		if err := client.writeJWTRole(ctx, vault.AuthMount, vault.Role, role); err != nil {
			return result, fmt.Errorf("write Vault JWT role %q: %w", vault.Role, err)
		}
		result.Roles++

		record := map[string]any{
			"ts":               time.Now().UTC().Format(time.RFC3339Nano),
			"event":            "vault_reconcile",
			"policyName":       compiled.PolicyName,
			"vaultPolicy":      policyName,
			"vaultRole":        vault.Role,
			"workloadIdentity": compiled.Workload.SPIFFEID,
			"secretPaths":      vaultSecretPolicyPaths(compiled),
			"outcome":          "applied",
		}
		_ = json.NewEncoder(opts.Audit).Encode(record)
	}

	return result, nil
}

type vaultRole struct {
	RoleType       string   `json:"role_type"`
	UserClaim      string   `json:"user_claim"`
	BoundAudiences []string `json:"bound_audiences"`
	BoundSubject   string   `json:"bound_subject"`
	TokenTTL       string   `json:"token_ttl"`
	TokenPolicies  []string `json:"token_policies"`
}

func (c vaultClient) writeACLPolicy(ctx context.Context, name string, acl string) error {
	return c.writeJSON(ctx, "/v1/sys/policies/acl/"+url.PathEscape(name), map[string]string{
		"policy": acl,
	})
}

func (c vaultClient) writeJWTRole(ctx context.Context, mount string, name string, role vaultRole) error {
	mount = strings.Trim(strings.TrimSpace(mount), "/")
	if mount == "" {
		return fmt.Errorf("auth mount is required")
	}
	return c.writeJSON(ctx, "/v1/auth/"+url.PathEscape(mount)+"/role/"+url.PathEscape(name), role)
}

func (c vaultClient) writeJSON(ctx context.Context, path string, value any) error {
	base := strings.TrimRight(strings.TrimSpace(c.address), "/")
	if base == "" {
		return fmt.Errorf("Vault address is required")
	}

	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("Vault returned %s: %s", resp.Status, strings.TrimSpace(string(responseBody)))
	}
	return nil
}

func vaultPolicyName(compiled policy.CompiledPolicy) string {
	return "airlock-" + dnsLabelPart(compiled.PolicyName)
}

func vaultACLPolicy(compiled policy.CompiledPolicy) (string, error) {
	paths := vaultSecretPolicyPaths(compiled)
	if len(paths) == 0 {
		return "", fmt.Errorf("no Vault secret refs found")
	}

	var b strings.Builder
	for _, path := range paths {
		if strings.ContainsAny(path, "\r\n") {
			return "", fmt.Errorf("secret path %q contains a newline", path)
		}
		fmt.Fprintf(&b, "path %s {\n  capabilities = [\"read\"]\n}\n", strconv.Quote(path))
	}
	return b.String(), nil
}

func vaultSecretPolicyPaths(compiled policy.CompiledPolicy) []string {
	seen := map[string]struct{}{}
	for _, rule := range compiled.Egress {
		for _, rewrite := range rule.Rewrites {
			ref := rewrite.ValueFrom
			if ref.Provider != "vault" || ref.Engine != "kv-v2" {
				continue
			}
			mount := strings.Trim(strings.TrimSpace(ref.Mount), "/")
			path := strings.Trim(strings.TrimSpace(ref.Path), "/")
			if mount == "" || path == "" {
				continue
			}
			seen[mount+"/data/"+path] = struct{}{}
		}
	}

	out := make([]string, 0, len(seen))
	for path := range seen {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func dnsLabelPart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var out strings.Builder
	lastDash := false
	for _, ch := range value {
		valid := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
		if valid {
			out.WriteRune(ch)
			lastDash = false
			continue
		}
		if !lastDash {
			out.WriteByte('-')
			lastDash = true
		}
	}
	clean := strings.Trim(out.String(), "-")
	if clean == "" {
		return "default"
	}
	return clean
}
