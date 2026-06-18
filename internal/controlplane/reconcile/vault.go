package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/marcammann/airlock/internal/names"
	"github.com/marcammann/airlock/internal/policy"
	"github.com/marcammann/airlock/internal/telemetry"
	"github.com/marcammann/airlock/internal/vaultpath"
	globalotel "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// VaultReconcileOptions configures reconciliation of Vault policies and JWT roles.
type VaultReconcileOptions struct {
	AdminToken string
	HTTPClient *http.Client
	Audit      io.Writer
}

// VaultReconcileResult summarizes one Vault reconciliation pass.
type VaultReconcileResult struct {
	Policies int
	Roles    int
}

type vaultClient struct {
	client *vaultapi.Client
}

// ReconcileVault applies Vault ACL policies and JWT roles for compiled policies.
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
	ctx, span := globalotel.Tracer("github.com/marcammann/airlock/controlplane").Start(ctx, "airlock.control_plane.reconcile_vault")
	defer span.End()
	startedAt := time.Now()
	defer func() {
		telemetry.ObserveControlPlaneReconcileDuration("vault", time.Since(startedAt))
	}()

	var result VaultReconcileResult
	for _, compiled := range store.Policies() {
		if compiled.SecretProvider == nil || compiled.SecretProvider.Vault == nil {
			continue
		}
		vault := compiled.SecretProvider.Vault
		client, err := newVaultReconcileClient(vault.Address, opts.AdminToken, opts.HTTPClient)
		if err != nil {
			return result, err
		}

		policyName := VaultPolicyName(compiled)
		acl, secretCount, err := VaultACLPolicy(compiled)
		if err != nil {
			return result, fmt.Errorf("build Vault ACL policy for %q: %w", compiled.PolicyName, err)
		}
		if err := client.writeACLPolicy(ctx, policyName, acl); err != nil {
			return result, fmt.Errorf("write Vault ACL policy %q: %w", policyName, err)
		}
		result.Policies++

		role := VaultRole{
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
			"workloadName":     compiled.PolicyName,
			"vaultPolicy":      policyName,
			"vaultRole":        vault.Role,
			"workloadIdentity": compiled.Workload.SPIFFEID,
			"secretCount":      secretCount,
			"outcome":          "applied",
		}
		if err := json.NewEncoder(opts.Audit).Encode(record); err != nil {
			slog.Error("write Vault reconcile audit record failed", "error", err, "record", record)
		}
	}

	span.SetAttributes(
		attribute.Int("vault.policies", result.Policies),
		attribute.Int("vault.roles", result.Roles),
	)
	return result, nil
}

// VaultRole is the subset of Vault's JWT auth role payload Airlock writes.
type VaultRole struct {
	RoleType       string   `json:"role_type"`
	UserClaim      string   `json:"user_claim"`
	BoundAudiences []string `json:"bound_audiences"`
	BoundSubject   string   `json:"bound_subject"`
	TokenTTL       string   `json:"token_ttl"`
	TokenPolicies  []string `json:"token_policies"`
}

func (c vaultClient) writeACLPolicy(ctx context.Context, name string, acl string) error {
	return c.client.Sys().PutPolicyWithContext(ctx, name, acl)
}

func (c vaultClient) writeJWTRole(ctx context.Context, mount string, name string, role VaultRole) error {
	mount = strings.Trim(strings.TrimSpace(mount), "/")
	if mount == "" {
		return fmt.Errorf("auth mount is required")
	}
	_, err := c.client.Logical().WriteWithContext(ctx, "auth/"+mount+"/role/"+name, map[string]any{
		"role_type":       role.RoleType,
		"user_claim":      role.UserClaim,
		"bound_audiences": role.BoundAudiences,
		"bound_subject":   role.BoundSubject,
		"token_ttl":       role.TokenTTL,
		"token_policies":  role.TokenPolicies,
	})
	return err
}

func newVaultReconcileClient(address string, token string, httpClient *http.Client) (vaultClient, error) {
	address = strings.TrimRight(strings.TrimSpace(address), "/")
	if address == "" {
		return vaultClient{}, fmt.Errorf("vault address is required")
	}
	config := vaultapi.DefaultConfig()
	config.Address = address
	config.HttpClient = httpClient
	client, err := vaultapi.NewClient(config)
	if err != nil {
		return vaultClient{}, err
	}
	client.SetToken(token)
	return vaultClient{client: client}, nil
}

// VaultPolicyName returns the generated Vault policy name for a compiled Airlock policy.
func VaultPolicyName(compiled policy.CompiledPolicy) string {
	return names.AirlockClusterResourceName(compiled.Workload.Namespace, compiled.PolicyName)
}

// VaultACLPolicy renders the Vault ACL policy for a compiled Airlock policy.
func VaultACLPolicy(compiled policy.CompiledPolicy) (string, int, error) {
	paths, err := VaultSecretPolicyPaths(compiled)
	if err != nil {
		return "", 0, err
	}
	if len(paths) == 0 {
		return "", 0, fmt.Errorf("no Vault secret refs found")
	}

	var b strings.Builder
	for _, path := range paths {
		if strings.ContainsAny(path, "\r\n") {
			return "", 0, fmt.Errorf("secret path %q contains a newline", path)
		}
		fmt.Fprintf(&b, "path %s {\n  capabilities = [\"read\"]\n}\n", strconv.Quote(path))
	}
	return b.String(), len(paths), nil
}

// VaultSecretPolicyPaths returns the Vault KV-v2 data paths referenced by a compiled policy.
func VaultSecretPolicyPaths(compiled policy.CompiledPolicy) ([]string, error) {
	seen := map[string]struct{}{}
	for _, rule := range compiled.Egress {
		for _, rewrite := range rule.Rewrites {
			ref := rewrite.ValueFrom
			if ref.Provider != "vault" || ref.Engine != "kv-v2" {
				continue
			}
			mount, secretPath, err := vaultpath.CleanKV2SecretPath(ref.Mount, ref.Path)
			if err != nil {
				return nil, err
			}
			if mount == "" || secretPath == "" {
				continue
			}
			seen[mount+"/data/"+secretPath] = struct{}{}
		}
	}

	out := make([]string, 0, len(seen))
	for path := range seen {
		out = append(out, path)
	}
	sort.Strings(out)
	return out, nil
}
