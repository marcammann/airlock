package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/marc/airlock/control-plane/internal/policy"
)

const (
	airlockAPIGroup   = "airlock.dev"
	airlockAPIVersion = "v1alpha1"
	serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
)

type KubernetesPolicySourceOptions struct {
	Namespace    string
	APIServerURL string
	TokenPath    string
	CAPath       string
	HTTPClient   *http.Client
	Audit        io.Writer
}

type KubernetesPolicyStatusUpdate struct {
	Policy policy.AirlockPolicy
	Status policy.Status
}

type kubernetesClient struct {
	baseURL string
	token   string
	client  *http.Client
}

func DefaultKubernetesPolicySourceOptions(namespace string) KubernetesPolicySourceOptions {
	return KubernetesPolicySourceOptions{
		Namespace:    namespace,
		APIServerURL: kubernetesAPIServerURLFromEnv(),
		TokenPath:    serviceAccountDir + "/token",
		CAPath:       serviceAccountDir + "/ca.crt",
	}
}

func LoadPolicyStoreFromKubernetes(ctx context.Context, opts KubernetesPolicySourceOptions) (*PolicyStore, []KubernetesPolicyStatusUpdate, error) {
	client, err := newKubernetesClient(opts)
	if err != nil {
		return nil, nil, err
	}
	namespace := strings.TrimSpace(opts.Namespace)
	if namespace == "" {
		return nil, nil, fmt.Errorf("Kubernetes policy namespace is required")
	}

	providerConfigs, err := listSecretProviderConfigs(ctx, client, namespace)
	if err != nil {
		return nil, nil, err
	}
	policies, err := listAirlockPolicies(ctx, client, namespace)
	if err != nil {
		return nil, nil, err
	}

	compiledPolicies := make([]policy.CompiledPolicy, 0, len(policies))
	updates := make([]KubernetesPolicyStatusUpdate, 0, len(policies))
	for _, input := range policies {
		providerConfig, err := resolveSecretProviderConfig(input, providerConfigs)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve secret provider for policy %s/%s: %w", input.Metadata.Namespace, input.Metadata.Name, err)
		}
		compiled, err := policy.CompileWithSecretProvider(input, providerConfig)
		if err != nil {
			return nil, nil, fmt.Errorf("compile policy %s/%s: %w", input.Metadata.Namespace, input.Metadata.Name, err)
		}
		compiledPolicies = append(compiledPolicies, compiled)
		updates = append(updates, KubernetesPolicyStatusUpdate{
			Policy: input,
			Status: readyPolicyStatus(input, compiled, false),
		})
	}

	store, err := NewPolicyStoreFromCompiled(compiledPolicies)
	if err != nil {
		return nil, nil, err
	}
	return store, updates, nil
}

func PatchAirlockPolicyStatus(ctx context.Context, opts KubernetesPolicySourceOptions, input policy.AirlockPolicy, status policy.Status) error {
	client, err := newKubernetesClient(opts)
	if err != nil {
		return err
	}
	namespace := strings.TrimSpace(input.Metadata.Namespace)
	if namespace == "" {
		namespace = strings.TrimSpace(opts.Namespace)
	}
	if namespace == "" || strings.TrimSpace(input.Metadata.Name) == "" {
		return fmt.Errorf("policy namespace and name are required for status patch")
	}

	path := namespacedAirlockPath(namespace, "airlockpolicies") + "/" + url.PathEscape(input.Metadata.Name) + "/status"
	return client.patchJSON(ctx, path, map[string]policy.Status{"status": status})
}

func readyPolicyStatus(input policy.AirlockPolicy, compiled policy.CompiledPolicy, vaultReady bool) policy.Status {
	status := "False"
	if vaultReady {
		status = "True"
	}
	return policy.Status{
		ObservedGeneration: input.Metadata.Generation,
		PolicyHash:         compiledPolicyHash(compiled),
		Spire:              policy.SubsystemStatus{Ready: true},
		Vault:              policy.SubsystemStatus{Ready: vaultReady},
		Conditions: []policy.StatusCondition{{
			Type:   "Ready",
			Status: status,
			Reason: func() string {
				if vaultReady {
					return "Reconciled"
				}
				return "Compiled"
			}(),
		}},
	}
}

func failedPolicyStatus(input policy.AirlockPolicy, reason string, message string) policy.Status {
	return policy.Status{
		ObservedGeneration: input.Metadata.Generation,
		Spire:              policy.SubsystemStatus{Ready: true},
		Vault:              policy.SubsystemStatus{Ready: false},
		Conditions: []policy.StatusCondition{{
			Type:    "Ready",
			Status:  "False",
			Reason:  reason,
			Message: message,
		}},
	}
}

func listSecretProviderConfigs(ctx context.Context, client kubernetesClient, namespace string) (map[string]policy.SecretProviderConfig, error) {
	var list struct {
		Items []policy.SecretProviderConfig `json:"items"`
	}
	if err := client.getJSON(ctx, namespacedAirlockPath(namespace, "secretproviderconfigs"), &list); err != nil {
		return nil, fmt.Errorf("list SecretProviderConfig objects: %w", err)
	}

	out := map[string]policy.SecretProviderConfig{}
	for _, item := range list.Items {
		if item.Metadata.Namespace == "" {
			item.Metadata.Namespace = namespace
		}
		if err := policy.ValidateSecretProviderConfig(item); err != nil {
			return nil, fmt.Errorf("validate SecretProviderConfig %s/%s: %w", item.Metadata.Namespace, item.Metadata.Name, err)
		}
		key := providerConfigKey(item.Metadata.Namespace, item.Metadata.Name)
		if existing, ok := out[key]; ok {
			return nil, fmt.Errorf("secret provider config %q duplicates %q", item.Metadata.Name, existing.Metadata.Name)
		}
		out[key] = item
	}
	return out, nil
}

func listAirlockPolicies(ctx context.Context, client kubernetesClient, namespace string) ([]policy.AirlockPolicy, error) {
	var list struct {
		Items []policy.AirlockPolicy `json:"items"`
	}
	if err := client.getJSON(ctx, namespacedAirlockPath(namespace, "airlockpolicies"), &list); err != nil {
		return nil, fmt.Errorf("list AirlockPolicy objects: %w", err)
	}
	for i := range list.Items {
		if list.Items[i].Metadata.Namespace == "" {
			list.Items[i].Metadata.Namespace = namespace
		}
	}
	return list.Items, nil
}

func newKubernetesClient(opts KubernetesPolicySourceOptions) (kubernetesClient, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(opts.APIServerURL), "/")
	if baseURL == "" {
		return kubernetesClient{}, fmt.Errorf("Kubernetes API server URL is required")
	}

	token := ""
	if strings.TrimSpace(opts.TokenPath) != "" {
		data, err := os.ReadFile(opts.TokenPath)
		if err == nil {
			token = strings.TrimSpace(string(data))
		} else if opts.HTTPClient == nil {
			return kubernetesClient{}, fmt.Errorf("read Kubernetes service account token: %w", err)
		}
	}

	client := opts.HTTPClient
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if strings.TrimSpace(opts.CAPath) != "" {
			ca, err := os.ReadFile(opts.CAPath)
			if err != nil {
				return kubernetesClient{}, fmt.Errorf("read Kubernetes CA bundle: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(ca) {
				return kubernetesClient{}, fmt.Errorf("parse Kubernetes CA bundle")
			}
			transport.TLSClientConfig = &tls.Config{RootCAs: pool}
		}
		client = &http.Client{Transport: transport, Timeout: 10 * time.Second}
	}

	return kubernetesClient{
		baseURL: baseURL,
		token:   token,
		client:  client,
	}, nil
}

func (c kubernetesClient) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	c.authorize(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("Kubernetes returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c kubernetesClient) patchJSON(ctx context.Context, path string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.authorize(req)
	req.Header.Set("Content-Type", "application/merge-patch+json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("Kubernetes returned %s: %s", resp.Status, strings.TrimSpace(string(responseBody)))
	}
	return nil
}

func (c kubernetesClient) authorize(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")
}

func namespacedAirlockPath(namespace string, resource string) string {
	return "/apis/" + airlockAPIGroup + "/" + airlockAPIVersion + "/namespaces/" + url.PathEscape(namespace) + "/" + resource
}

func kubernetesAPIServerURLFromEnv() string {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS"))
	if port == "" {
		port = strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	}
	if host == "" || port == "" {
		return ""
	}
	return "https://" + host + ":" + port
}

func compiledPolicyHash(compiled policy.CompiledPolicy) string {
	data, _ := json.Marshal(compiled)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
