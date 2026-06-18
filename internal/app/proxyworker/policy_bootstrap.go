package proxyworker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/marcammann/airlock/internal/proxyworker/egress"
	workerpolicy "github.com/marcammann/airlock/internal/proxyworker/policy"
)

type initialPolicyOptions struct {
	NoControlPlane           bool
	PolicyPath               string
	ControlPlaneURL          string
	ControlPlaneAuth         string
	ControlPlaneAuthExplicit bool
	Insecure                 bool
	WorkloadIdentity         string
	EnrollmentToken          string
	EnrollmentTokenFile      string
	ControlPlaneServerID     string
	SPIFFESocket             string
}

type initialPolicyResult struct {
	Policy       egress.CompiledPolicy
	FetchedAt    *time.Time
	ETag         string
	Provider     workerpolicy.ControlPlanePolicyProvider
	Client       *http.Client
	ClientCloser io.Closer
}

func loadInitialPolicy(ctx context.Context, opts initialPolicyOptions) (initialPolicyResult, error) {
	if opts.NoControlPlane {
		if opts.PolicyPath == "" {
			return initialPolicyResult{}, fmt.Errorf("--no-control-plane requires --policy")
		}
		if opts.ControlPlaneURL != "" {
			return initialPolicyResult{}, fmt.Errorf("--no-control-plane cannot use --control-plane-url")
		}
		if hasEnrollmentTokenInput(opts.EnrollmentToken, opts.EnrollmentTokenFile) {
			return initialPolicyResult{}, fmt.Errorf("--no-control-plane cannot use --enrollment-token or --enrollment-token-file")
		}
		policy, err := workerpolicy.NewLocalPolicyProvider(opts.PolicyPath).Load()
		if err != nil {
			return initialPolicyResult{}, err
		}
		return initialPolicyResult{Policy: policy}, nil
	}

	if opts.PolicyPath != "" {
		return initialPolicyResult{}, fmt.Errorf("control-plane mode uses control-plane policy; remove --policy or add --no-control-plane")
	}
	if opts.ControlPlaneURL == "" {
		return initialPolicyResult{}, fmt.Errorf("control-plane mode requires --control-plane-url")
	}
	provider := workerpolicy.NewControlPlanePolicyProvider(opts.ControlPlaneURL, opts.WorkloadIdentity)
	if err := validateControlPlaneAuth(opts.ControlPlaneAuth, opts.ControlPlaneAuthExplicit, opts.Insecure, opts.EnrollmentToken, opts.EnrollmentTokenFile); err != nil {
		return initialPolicyResult{}, err
	}

	var result initialPolicyResult
	result.Provider = provider
	now := time.Now().UTC()
	result.FetchedAt = &now
	if opts.Insecure {
		if opts.WorkloadIdentity == "" {
			return initialPolicyResult{}, fmt.Errorf("--insecure requires --workload-identity")
		}
		poll, err := provider.Poll(ctx, nil, "")
		if err != nil {
			return initialPolicyResult{}, err
		}
		result.Policy = poll.Policy
		result.ETag = poll.ETag
		return result, nil
	}

	switch opts.ControlPlaneAuth {
	case "spiffe":
		if opts.WorkloadIdentity == "" {
			return initialPolicyResult{}, fmt.Errorf("--control-plane-auth spiffe requires --workload-identity")
		}
		if opts.ControlPlaneServerID == "" {
			return initialPolicyResult{}, fmt.Errorf("--control-plane-auth spiffe requires --control-plane-server-id")
		}
		client, closer, err := workerpolicy.NewSPIFFEMTLSHTTPClient(ctx, opts.ControlPlaneServerID, opts.SPIFFESocket, 15*time.Second)
		if err != nil {
			return initialPolicyResult{}, err
		}
		poll, err := provider.Poll(ctx, client, "")
		if err != nil {
			_ = closer.Close()
			return initialPolicyResult{}, err
		}
		result.Policy = poll.Policy
		result.ETag = poll.ETag
		result.Client = client
		result.ClientCloser = closer
		return result, nil
	case "enrollment":
		token, err := resolveEnrollmentToken(opts.EnrollmentToken, opts.EnrollmentTokenFile)
		if err != nil {
			return initialPolicyResult{}, err
		}
		policy, err := workerpolicy.NewEnrollmentPolicyProvider(opts.ControlPlaneURL, token).Load(ctx)
		if err != nil {
			return initialPolicyResult{}, err
		}
		result.Policy = policy
		return result, nil
	default:
		return initialPolicyResult{}, fmt.Errorf("unsupported control-plane auth %q; use spiffe or enrollment", opts.ControlPlaneAuth)
	}
}

func validateControlPlaneAuth(auth string, authExplicit bool, insecure bool, enrollmentToken string, enrollmentTokenFile string) error {
	if insecure {
		if authExplicit {
			return fmt.Errorf("--insecure cannot be combined with --control-plane-auth")
		}
		if hasEnrollmentTokenInput(enrollmentToken, enrollmentTokenFile) {
			return fmt.Errorf("--insecure cannot use --enrollment-token or --enrollment-token-file")
		}
		return nil
	}
	switch auth {
	case "spiffe":
		if hasEnrollmentTokenInput(enrollmentToken, enrollmentTokenFile) {
			if authExplicit {
				return fmt.Errorf("--enrollment-token and --enrollment-token-file cannot be combined with --control-plane-auth spiffe")
			}
			return nil
		}
		return nil
	case "enrollment":
		if strings.TrimSpace(enrollmentToken) == "" && strings.TrimSpace(enrollmentTokenFile) == "" {
			return fmt.Errorf("--control-plane-auth enrollment requires --enrollment-token or --enrollment-token-file")
		}
		return nil
	case "none":
		return fmt.Errorf("use --insecure instead of --control-plane-auth none")
	default:
		return fmt.Errorf("unsupported control-plane auth %q; use spiffe or enrollment", auth)
	}
}

func hasEnrollmentTokenInput(value string, file string) bool {
	return strings.TrimSpace(value) != "" || strings.TrimSpace(file) != ""
}

func resolveEnrollmentToken(value string, file string) (string, error) {
	value = strings.TrimSpace(value)
	file = strings.TrimSpace(file)
	if value != "" && file != "" {
		return "", fmt.Errorf("--enrollment-token and --enrollment-token-file are mutually exclusive")
	}
	if value != "" {
		return value, nil
	}
	if file == "" {
		return "", fmt.Errorf("enrollment token is required")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("read enrollment token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("enrollment token file is empty")
	}
	return token, nil
}
