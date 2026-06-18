// Package reconcile contains control-plane reconcilers for external systems
// derived from Airlock workloads.
package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	controlstore "github.com/marcammann/airlock/internal/controlplane/store"
	"github.com/marcammann/airlock/internal/names"
	"github.com/marcammann/airlock/internal/policy"
	"github.com/marcammann/airlock/internal/telemetry"
	globalotel "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	spireAPIGroup   = "spire.spiffe.io"
	spireAPIVersion = "v1alpha1"
)

var (
	// SPIREClusterSPIFFEIDGVK identifies SPIRE ClusterSPIFFEID objects.
	SPIREClusterSPIFFEIDGVK = schema.GroupVersionKind{Group: spireAPIGroup, Version: spireAPIVersion, Kind: "ClusterSPIFFEID"}
	// SPIREClusterSPIFFEIDListGVK identifies SPIRE ClusterSPIFFEID list objects.
	SPIREClusterSPIFFEIDListGVK = schema.GroupVersionKind{Group: spireAPIGroup, Version: spireAPIVersion, Kind: "ClusterSPIFFEIDList"}
)

// PolicyStore is the reconciler view of compiled Airlock policies.
type PolicyStore = controlstore.PolicyStore

// SPIREReconcileOptions configures reconciliation of SPIRE ClusterSPIFFEID resources.
type SPIREReconcileOptions struct {
	Client         ctrlclient.Client
	ClassName      string
	PodLabel       string
	PodValue       string
	GarbageCollect bool
	Audit          io.Writer
}

// SPIREReconcileResult summarizes one SPIRE reconciliation pass.
type SPIREReconcileResult struct {
	ClusterSPIFFEIDs        int
	DeletedClusterSPIFFEIDs int
}

// ReconcileSPIRE applies SPIRE ClusterSPIFFEID resources for all compiled policies.
func ReconcileSPIRE(ctx context.Context, store *PolicyStore, opts SPIREReconcileOptions) (SPIREReconcileResult, error) {
	if store == nil {
		return SPIREReconcileResult{}, fmt.Errorf("policy store is nil")
	}
	opts = normalizeSPIREReconcileOptions(opts)
	ctx, span := globalotel.Tracer("github.com/marcammann/airlock/controlplane").Start(ctx, "airlock.control_plane.reconcile_spire")
	defer span.End()
	startedAt := time.Now()
	defer func() {
		telemetry.ObserveControlPlaneReconcileDuration("spire", time.Since(startedAt))
	}()

	if opts.Client == nil {
		return SPIREReconcileResult{}, fmt.Errorf("kubernetes client is required for SPIRE reconciliation")
	}

	result, err := reconcileSPIREWithClient(ctx, store, opts.Client, opts)
	if err == nil {
		span.SetAttributes(
			attribute.Int("spire.cluster_spiffe_ids", result.ClusterSPIFFEIDs),
			attribute.Int("spire.deleted_cluster_spiffe_ids", result.DeletedClusterSPIFFEIDs),
		)
	}
	return result, err
}

func normalizeSPIREReconcileOptions(opts SPIREReconcileOptions) SPIREReconcileOptions {
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
	return opts
}

// ClusterSPIFFEID is the subset of the SPIRE ClusterSPIFFEID resource Airlock reconciles.
type ClusterSPIFFEID struct {
	APIVersion string              `json:"apiVersion"`
	Kind       string              `json:"kind"`
	Metadata   ClusterObjectMeta   `json:"metadata"`
	Spec       ClusterSPIFFEIDSpec `json:"spec"`
}

// ClusterObjectMeta is the object metadata Airlock writes to cluster-scoped resources.
type ClusterObjectMeta struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
}

// ClusterSPIFFEIDSpec is the SPIRE ClusterSPIFFEID spec Airlock reconciles.
type ClusterSPIFFEIDSpec struct {
	ClassName         string        `json:"className,omitempty"`
	SPIFFEIDTemplate  string        `json:"spiffeIDTemplate"`
	PodSelector       LabelSelector `json:"podSelector"`
	NamespaceSelector LabelSelector `json:"namespaceSelector"`
}

// LabelSelector is the label selector shape used by SPIRE ClusterSPIFFEID.
type LabelSelector struct {
	MatchLabels map[string]string `json:"matchLabels"`
}

func reconcileSPIREWithClient(ctx context.Context, store *PolicyStore, kube ctrlclient.Client, opts SPIREReconcileOptions) (SPIREReconcileResult, error) {
	var result SPIREReconcileResult
	desired := map[string]struct{}{}
	for _, compiled := range store.Policies() {
		object, err := ClusterSPIFFEIDForWorkload(compiled, opts)
		if err != nil {
			return result, err
		}
		desired[object.Metadata.Name] = struct{}{}
		if err := upsertClusterSPIFFEIDWithClient(ctx, kube, object); err != nil {
			return result, fmt.Errorf("upsert ClusterSPIFFEID %q: %w", object.Metadata.Name, err)
		}
		result.ClusterSPIFFEIDs++
		recordSPIREApplied(opts.Audit, compiled, object)
	}

	if opts.GarbageCollect {
		deleted, err := garbageCollectClusterSPIFFEIDsWithClient(ctx, kube, desired, opts.Audit)
		if err != nil {
			return result, err
		}
		result.DeletedClusterSPIFFEIDs = deleted
	}
	return result, nil
}

// ClusterSPIFFEIDForWorkload builds the desired SPIRE ClusterSPIFFEID for a compiled policy.
func ClusterSPIFFEIDForWorkload(compiled policy.CompiledPolicy, opts SPIREReconcileOptions) (ClusterSPIFFEID, error) {
	workloadNamespace := strings.TrimSpace(compiled.Workload.Namespace)
	if workloadNamespace == "" {
		return ClusterSPIFFEID{}, fmt.Errorf("workload %q has empty workload namespace", compiled.PolicyName)
	}
	workloadIdentity := strings.TrimSpace(compiled.Workload.SPIFFEID)
	if workloadIdentity == "" {
		return ClusterSPIFFEID{}, fmt.Errorf("workload %q has empty workload SPIFFE ID", compiled.PolicyName)
	}

	name := names.AirlockClusterResourceName(workloadNamespace, compiled.PolicyName)
	return ClusterSPIFFEID{
		APIVersion: spireAPIGroup + "/" + spireAPIVersion,
		Kind:       "ClusterSPIFFEID",
		Metadata: ClusterObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app.kubernetes.io/name":    "airlock-control-plane",
				"app.kubernetes.io/part-of": "airlock",
				"airlock.dev/workload-name": compiled.PolicyName,
				"airlock.dev/managed-by":    "airlock-control-plane",
			},
		},
		Spec: ClusterSPIFFEIDSpec{
			ClassName:        strings.TrimSpace(opts.ClassName),
			SPIFFEIDTemplate: workloadIdentity,
			PodSelector: LabelSelector{MatchLabels: map[string]string{
				strings.TrimSpace(opts.PodLabel): strings.TrimSpace(opts.PodValue),
			}},
			NamespaceSelector: LabelSelector{MatchLabels: map[string]string{
				"kubernetes.io/metadata.name": workloadNamespace,
			}},
		},
	}, nil
}

func upsertClusterSPIFFEIDWithClient(ctx context.Context, kube ctrlclient.Client, object ClusterSPIFFEID) error {
	current := NewClusterSPIFFEIDUnstructured()
	err := kube.Get(ctx, ctrlclient.ObjectKey{Name: object.Metadata.Name}, current)
	if apierrors.IsNotFound(err) {
		desired, err := clusterSPIFFEIDToUnstructured(object)
		if err != nil {
			return err
		}
		return kube.Create(ctx, desired)
	}
	if err != nil {
		return err
	}

	current.SetLabels(object.Metadata.Labels)
	current.Object["spec"] = ClusterSPIFFEIDSpecMap(object.Spec)
	return kube.Update(ctx, current)
}

func garbageCollectClusterSPIFFEIDsWithClient(ctx context.Context, kube ctrlclient.Client, desired map[string]struct{}, audit io.Writer) (int, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(SPIREClusterSPIFFEIDListGVK)
	if err := kube.List(ctx, list, ctrlclient.MatchingLabels{"airlock.dev/managed-by": "airlock-control-plane"}); err != nil {
		return 0, fmt.Errorf("list managed ClusterSPIFFEIDs: %w", err)
	}

	deleted := 0
	for i := range list.Items {
		item := &list.Items[i]
		item.SetGroupVersionKind(SPIREClusterSPIFFEIDGVK)
		name := strings.TrimSpace(item.GetName())
		if name == "" {
			continue
		}
		if _, ok := desired[name]; ok {
			continue
		}
		if err := kube.Delete(ctx, item); err != nil && !apierrors.IsNotFound(err) {
			return deleted, fmt.Errorf("delete stale ClusterSPIFFEID %q: %w", name, err)
		}
		deleted++
		recordSPIREDeleted(audit, name)
	}
	return deleted, nil
}

func clusterSPIFFEIDToUnstructured(object ClusterSPIFFEID) (*unstructured.Unstructured, error) {
	out := NewClusterSPIFFEIDUnstructured()
	out.SetName(object.Metadata.Name)
	out.SetLabels(object.Metadata.Labels)
	out.Object["spec"] = ClusterSPIFFEIDSpecMap(object.Spec)
	return out, nil
}

// NewClusterSPIFFEIDUnstructured returns an unstructured SPIRE ClusterSPIFFEID object.
func NewClusterSPIFFEIDUnstructured() *unstructured.Unstructured {
	out := &unstructured.Unstructured{}
	out.SetGroupVersionKind(SPIREClusterSPIFFEIDGVK)
	return out
}

// ClusterSPIFFEIDSpecMap converts a ClusterSPIFFEID spec into an unstructured map.
func ClusterSPIFFEIDSpecMap(spec ClusterSPIFFEIDSpec) map[string]any {
	return map[string]any{
		"className":        spec.ClassName,
		"spiffeIDTemplate": spec.SPIFFEIDTemplate,
		"podSelector": map[string]any{
			"matchLabels": stringMapAny(spec.PodSelector.MatchLabels),
		},
		"namespaceSelector": map[string]any{
			"matchLabels": stringMapAny(spec.NamespaceSelector.MatchLabels),
		},
	}
}

func stringMapAny(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func recordSPIREApplied(audit io.Writer, compiled policy.CompiledPolicy, object ClusterSPIFFEID) {
	record := map[string]any{
		"ts":                  time.Now().UTC().Format(time.RFC3339Nano),
		"event":               "spire_reconcile",
		"outcome":             "applied",
		"workloadName":        compiled.PolicyName,
		"clusterSPIFFEID":     object.Metadata.Name,
		"workloadIdentity":    compiled.Workload.SPIFFEID,
		"workloadNamespace":   compiled.Workload.Namespace,
		"workloadPodSelector": object.Spec.PodSelector.MatchLabels,
	}
	if err := json.NewEncoder(audit).Encode(record); err != nil {
		slog.Error("write SPIRE reconcile audit record failed", "error", err, "record", record)
	}
}

func recordSPIREDeleted(audit io.Writer, name string) {
	record := map[string]any{
		"ts":              time.Now().UTC().Format(time.RFC3339Nano),
		"event":           "spire_reconcile",
		"outcome":         "deleted",
		"clusterSPIFFEID": name,
	}
	if err := json.NewEncoder(audit).Encode(record); err != nil {
		slog.Error("write SPIRE reconcile audit record failed", "error", err, "record", record)
	}
}
