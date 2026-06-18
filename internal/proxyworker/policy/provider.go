// Package policy loads and polls compiled policies for proxy workers.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"gopkg.in/yaml.v3"
)

const maxPolicyResponseBytes = 4 << 20

// LocalPolicyProvider loads a compiled policy from disk.
type LocalPolicyProvider struct {
	path string
}

// NewLocalPolicyProvider creates a file-backed compiled policy provider.
func NewLocalPolicyProvider(path string) LocalPolicyProvider {
	return LocalPolicyProvider{path: path}
}

// Load reads, parses, and validates the configured local policy file.
func (p LocalPolicyProvider) Load() (CompiledPolicy, error) {
	return LoadPolicyFile(p.path)
}

// LoadPolicyFile reads, parses, and validates one compiled policy file.
func LoadPolicyFile(path string) (CompiledPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CompiledPolicy{}, err
	}
	var policy CompiledPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return CompiledPolicy{}, err
	}
	if err := ValidateCompiledPolicy(policy); err != nil {
		return CompiledPolicy{}, err
	}
	return policy, nil
}

// ControlPlanePolicyProvider fetches compiled policies from the control plane.
type ControlPlanePolicyProvider struct {
	baseURL          string
	workloadIdentity string
}

// PolicyPollResult is the result of one conditional policy fetch.
type PolicyPollResult struct {
	Policy      CompiledPolicy
	ETag        string
	NotModified bool
}

// NewControlPlanePolicyProvider creates a control-plane policy provider.
func NewControlPlanePolicyProvider(baseURL, workloadIdentity string) ControlPlanePolicyProvider {
	return ControlPlanePolicyProvider{baseURL: baseURL, workloadIdentity: workloadIdentity}
}

// Poll conditionally fetches a policy and returns NotModified for HTTP 304 responses.
func (p ControlPlanePolicyProvider) Poll(ctx context.Context, client *http.Client, previousETag string) (PolicyPollResult, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(p.baseURL), "/")
	if baseURL == "" {
		return PolicyPollResult{}, fmt.Errorf("control plane URL is required")
	}
	if strings.TrimSpace(p.workloadIdentity) == "" {
		return PolicyPollResult{}, fmt.Errorf("workload identity is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	requestURL := baseURL + "/v1/policies/" + percentEncodePathSegment(p.workloadIdentity)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return PolicyPollResult{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "airlock-proxy-worker/0.1")
	if strings.TrimSpace(previousETag) != "" {
		req.Header.Set("If-None-Match", strings.TrimSpace(previousETag))
	}
	resp, err := client.Do(req)
	if err != nil {
		return PolicyPollResult{}, fmt.Errorf("fetch policy: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return PolicyPollResult{ETag: strings.TrimSpace(resp.Header.Get("ETag")), NotModified: true}, nil
	}
	body, err := readPolicyResponseBody(resp.Body)
	if err != nil {
		return PolicyPollResult{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return PolicyPollResult{}, fmt.Errorf("control plane returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var policy CompiledPolicy
	if err := json.Unmarshal(body, &policy); err != nil {
		return PolicyPollResult{}, err
	}
	if err := ValidateCompiledPolicy(policy); err != nil {
		return PolicyPollResult{}, err
	}
	return PolicyPollResult{Policy: policy, ETag: strings.TrimSpace(resp.Header.Get("ETag"))}, nil
}

// Load fetches the policy without using an existing ETag.
func (p ControlPlanePolicyProvider) Load() (CompiledPolicy, error) {
	result, err := p.Poll(context.Background(), nil, "")
	if err != nil {
		return CompiledPolicy{}, err
	}
	return result.Policy, nil
}

// EnrollmentPolicyProvider redeems an enrollment token for an initial policy.
type EnrollmentPolicyProvider struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewEnrollmentPolicyProvider creates an enrollment-token policy provider.
func NewEnrollmentPolicyProvider(baseURL, token string) EnrollmentPolicyProvider {
	return EnrollmentPolicyProvider{baseURL: baseURL, token: token}
}

// Load redeems the enrollment token and validates the returned policy.
func (p EnrollmentPolicyProvider) Load(ctx context.Context) (CompiledPolicy, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(p.baseURL), "/")
	if baseURL == "" {
		return CompiledPolicy{}, fmt.Errorf("control plane URL is required")
	}
	if strings.TrimSpace(p.token) == "" {
		return CompiledPolicy{}, fmt.Errorf("enrollment token is required")
	}
	client := p.client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/enrollments/redeem", nil)
	if err != nil {
		return CompiledPolicy{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(p.token))
	req.Header.Set("User-Agent", "airlock-proxy-worker/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return CompiledPolicy{}, fmt.Errorf("redeem enrollment token: %w", err)
	}
	defer resp.Body.Close()
	body, err := readPolicyResponseBody(resp.Body)
	if err != nil {
		return CompiledPolicy{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return CompiledPolicy{}, fmt.Errorf("redeem enrollment token returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Policy CompiledPolicy `json:"policy"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return CompiledPolicy{}, err
	}
	if err := ValidateCompiledPolicy(out.Policy); err != nil {
		return CompiledPolicy{}, err
	}
	return out.Policy, nil
}

// LoadSPIFFEMTLS fetches a policy over SPIFFE-authenticated mTLS.
func (p ControlPlanePolicyProvider) LoadSPIFFEMTLS(ctx context.Context, serverSPIFFEID, spiffeSocket string) (CompiledPolicy, error) {
	target, err := url.Parse(strings.TrimSpace(p.baseURL))
	if err != nil {
		return CompiledPolicy{}, err
	}
	if target.Scheme != "https" {
		return CompiledPolicy{}, fmt.Errorf("spiffe control-plane auth requires an https:// control-plane URL")
	}
	slog.Info("airlock-proxy-worker requesting policy over SPIFFE mTLS", "workload", p.workloadIdentity, "controlPlaneURL", p.baseURL, "expectedServerID", serverSPIFFEID)
	client, source, err := NewSPIFFEMTLSHTTPClient(ctx, serverSPIFFEID, spiffeSocket, 15*time.Second)
	if err != nil {
		return CompiledPolicy{}, err
	}
	defer source.Close()

	requestURL := strings.TrimRight(p.baseURL, "/") + "/v1/policies/" + percentEncodePathSegment(p.workloadIdentity)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return CompiledPolicy{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "airlock-proxy-worker/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return CompiledPolicy{}, fmt.Errorf("fetch policy over SPIFFE mTLS: %w", err)
	}
	defer resp.Body.Close()
	body, err := readPolicyResponseBody(resp.Body)
	if err != nil {
		return CompiledPolicy{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return CompiledPolicy{}, fmt.Errorf("control plane returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	slog.Info("airlock-proxy-worker policy fetch over SPIFFE mTLS succeeded", "bytes", len(body))
	var policy CompiledPolicy
	if err := json.Unmarshal(body, &policy); err != nil {
		return CompiledPolicy{}, err
	}
	if err := ValidateCompiledPolicy(policy); err != nil {
		return CompiledPolicy{}, err
	}
	return policy, nil
}

func readPolicyResponseBody(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxPolicyResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPolicyResponseBytes {
		return nil, errors.New("policy response exceeds 4 MiB limit")
	}
	return data, nil
}

// NewSPIFFEMTLSHTTPClient creates an HTTP client authorized for one control-plane SPIFFE ID.
func NewSPIFFEMTLSHTTPClient(ctx context.Context, serverSPIFFEID, spiffeSocket string, timeout time.Duration) (*http.Client, io.Closer, error) {
	serverID, err := spiffeid.FromString(serverSPIFFEID)
	if err != nil {
		return nil, nil, fmt.Errorf("parse control-plane SPIFFE ID: %w", err)
	}
	var opts []workloadapi.X509SourceOption
	if strings.TrimSpace(spiffeSocket) != "" {
		opts = append(opts, workloadapi.WithClientOptions(workloadapi.WithAddr(spiffeSocket)))
	}
	source, err := workloadapi.NewX509Source(ctx, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("create SPIFFE X509 source: %w", err)
	}
	if svid, err := source.GetX509SVID(); err == nil {
		slog.Info("airlock-proxy-worker selected SPIFFE X509 SVID", "spiffeID", svid.ID.String(), "chainLen", len(svid.Certificates), "sourceInitialSync", "complete")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(serverID)),
		},
	}
	return client, source, nil
}

func percentEncodePathSegment(value string) string {
	return strings.ReplaceAll(url.PathEscape(value), ":", "%3A")
}
