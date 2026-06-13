package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/marc/airlock/control-plane/internal/policy"
)

const (
	spireAPIGroup   = "spire.spiffe.io"
	spireAPIVersion = "v1alpha1"
)

type SPIREReconcileOptions struct {
	Kubernetes     KubernetesPolicySourceOptions
	ClassName      string
	PodLabel       string
	PodValue       string
	GarbageCollect bool
	Audit          io.Writer
}

type SPIREReconcileResult struct {
	ClusterSPIFFEIDs        int
	DeletedClusterSPIFFEIDs int
}

func ReconcileSPIRE(ctx context.Context, store *PolicyStore, opts SPIREReconcileOptions) (SPIREReconcileResult, error) {
	if store == nil {
		return SPIREReconcileResult{}, fmt.Errorf("policy store is nil")
	}
	if opts.Audit == nil {
		opts.Audit = io.Discard
	}
	if strings.TrimSpace(opts.ClassName) == "" {
		opts.ClassName = "spire-system-spire"
	}
	if strings.TrimSpace(opts.PodLabel) == "" {
		opts.PodLabel = "app.kubernetes.io/name"
	}
	if strings.TrimSpace(opts.PodValue) == "" {
		opts.PodValue = "airlock-proxy-worker"
	}

	client, err := newKubernetesClient(opts.Kubernetes)
	if err != nil {
		return SPIREReconcileResult{}, err
	}

	var result SPIREReconcileResult
	desired := map[string]struct{}{}
	for _, compiled := range store.Policies() {
		object, err := clusterSPIFFEIDForPolicy(compiled, opts)
		if err != nil {
			return result, err
		}
		desired[object.Metadata.Name] = struct{}{}
		if err := upsertClusterSPIFFEID(ctx, client, object); err != nil {
			return result, fmt.Errorf("upsert ClusterSPIFFEID %q: %w", object.Metadata.Name, err)
		}
		result.ClusterSPIFFEIDs++

		record := map[string]any{
			"ts":                  time.Now().UTC().Format(time.RFC3339Nano),
			"event":               "spire_reconcile",
			"outcome":             "applied",
			"policyName":          compiled.PolicyName,
			"clusterSPIFFEID":     object.Metadata.Name,
			"workloadIdentity":    compiled.Workload.SPIFFEID,
			"workloadNamespace":   compiled.Workload.Namespace,
			"workloadPodSelector": object.Spec.PodSelector.MatchLabels,
		}
		_ = json.NewEncoder(opts.Audit).Encode(record)
	}

	if opts.GarbageCollect {
		deleted, err := garbageCollectClusterSPIFFEIDs(ctx, client, desired, opts.Audit)
		if err != nil {
			return result, err
		}
		result.DeletedClusterSPIFFEIDs = deleted
	}
	return result, nil
}

type clusterSPIFFEID struct {
	APIVersion string              `json:"apiVersion"`
	Kind       string              `json:"kind"`
	Metadata   clusterObjectMeta   `json:"metadata"`
	Spec       clusterSPIFFEIDSpec `json:"spec"`
}

type clusterObjectMeta struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
}

type clusterSPIFFEIDSpec struct {
	ClassName         string        `json:"className,omitempty"`
	SPIFFEIDTemplate  string        `json:"spiffeIDTemplate"`
	PodSelector       labelSelector `json:"podSelector"`
	NamespaceSelector labelSelector `json:"namespaceSelector"`
}

type labelSelector struct {
	MatchLabels map[string]string `json:"matchLabels"`
}

func clusterSPIFFEIDForPolicy(compiled policy.CompiledPolicy, opts SPIREReconcileOptions) (clusterSPIFFEID, error) {
	workloadNamespace := strings.TrimSpace(compiled.Workload.Namespace)
	if workloadNamespace == "" {
		return clusterSPIFFEID{}, fmt.Errorf("policy %q has empty workload namespace", compiled.PolicyName)
	}
	workloadIdentity := strings.TrimSpace(compiled.Workload.SPIFFEID)
	if workloadIdentity == "" {
		return clusterSPIFFEID{}, fmt.Errorf("policy %q has empty workload SPIFFE ID", compiled.PolicyName)
	}

	name := "airlock-" + dnsLabelPart(compiled.PolicyName)
	return clusterSPIFFEID{
		APIVersion: spireAPIGroup + "/" + spireAPIVersion,
		Kind:       "ClusterSPIFFEID",
		Metadata: clusterObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app.kubernetes.io/name":    "airlock-control-plane",
				"app.kubernetes.io/part-of": "airlock",
				"airlock.dev/policy-name":   compiled.PolicyName,
				"airlock.dev/managed-by":    "airlock-control-plane",
			},
		},
		Spec: clusterSPIFFEIDSpec{
			ClassName:        strings.TrimSpace(opts.ClassName),
			SPIFFEIDTemplate: workloadIdentity,
			PodSelector: labelSelector{MatchLabels: map[string]string{
				strings.TrimSpace(opts.PodLabel): strings.TrimSpace(opts.PodValue),
			}},
			NamespaceSelector: labelSelector{MatchLabels: map[string]string{
				"kubernetes.io/metadata.name": workloadNamespace,
			}},
		},
	}, nil
}

func upsertClusterSPIFFEID(ctx context.Context, client kubernetesClient, object clusterSPIFFEID) error {
	path := clusterSPIFFEIDPath(object.Metadata.Name)
	patch, err := clusterSPIFFEIDReplacePatch(object)
	if err != nil {
		return err
	}

	status, body, err := client.patchJSONPatchRaw(ctx, path, patch)
	if err != nil {
		return err
	}
	if status >= 200 && status < 300 {
		return nil
	}
	if status != http.StatusNotFound {
		return fmt.Errorf("Kubernetes returned %d: %s", status, strings.TrimSpace(string(body)))
	}

	createBody, err := json.Marshal(object)
	if err != nil {
		return err
	}
	status, body, err = client.postJSONRaw(ctx, clusterSPIFFEIDCollectionPath(), createBody)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("Kubernetes returned %d: %s", status, strings.TrimSpace(string(body)))
	}
	return nil
}

func clusterSPIFFEIDReplacePatch(object clusterSPIFFEID) ([]byte, error) {
	return json.Marshal([]map[string]any{
		{
			"op":    "add",
			"path":  "/metadata/labels",
			"value": object.Metadata.Labels,
		},
		{
			"op":    "replace",
			"path":  "/spec",
			"value": object.Spec,
		},
	})
}

func garbageCollectClusterSPIFFEIDs(ctx context.Context, client kubernetesClient, desired map[string]struct{}, audit io.Writer) (int, error) {
	var list struct {
		Items []clusterSPIFFEID `json:"items"`
	}
	if err := client.getJSON(ctx, managedClusterSPIFFEIDCollectionPath(), &list); err != nil {
		return 0, fmt.Errorf("list managed ClusterSPIFFEIDs: %w", err)
	}

	deleted := 0
	for _, item := range list.Items {
		name := strings.TrimSpace(item.Metadata.Name)
		if name == "" {
			continue
		}
		if _, ok := desired[name]; ok {
			continue
		}
		if err := deleteClusterSPIFFEID(ctx, client, name); err != nil {
			return deleted, fmt.Errorf("delete stale ClusterSPIFFEID %q: %w", name, err)
		}
		deleted++
		record := map[string]any{
			"ts":              time.Now().UTC().Format(time.RFC3339Nano),
			"event":           "spire_reconcile",
			"outcome":         "deleted",
			"clusterSPIFFEID": name,
		}
		_ = json.NewEncoder(audit).Encode(record)
	}
	return deleted, nil
}

func deleteClusterSPIFFEID(ctx context.Context, client kubernetesClient, name string) error {
	status, body, err := client.deleteRaw(ctx, clusterSPIFFEIDPath(name))
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("Kubernetes returned %d: %s", status, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c kubernetesClient) patchJSONPatchRaw(ctx context.Context, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	c.authorize(req)
	req.Header.Set("Content-Type", "application/json-patch+json")
	return c.doRaw(req)
}

func (c kubernetesClient) postJSONRaw(ctx context.Context, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	c.authorize(req)
	req.Header.Set("Content-Type", "application/json")
	return c.doRaw(req)
}

func (c kubernetesClient) deleteRaw(ctx context.Context, path string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return 0, nil, err
	}
	c.authorize(req)
	return c.doRaw(req)
}

func (c kubernetesClient) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, body, nil
}

func clusterSPIFFEIDCollectionPath() string {
	return "/apis/" + spireAPIGroup + "/" + spireAPIVersion + "/clusterspiffeids"
}

func managedClusterSPIFFEIDCollectionPath() string {
	values := url.Values{}
	values.Set("labelSelector", "airlock.dev/managed-by=airlock-control-plane")
	return clusterSPIFFEIDCollectionPath() + "?" + values.Encode()
}

func clusterSPIFFEIDPath(name string) string {
	return clusterSPIFFEIDCollectionPath() + "/" + url.PathEscape(name)
}
