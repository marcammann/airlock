package controlplane

import (
	"net/http"

	controlwebhook "github.com/marcammann/airlock/internal/controlplane/webhook"
	"github.com/marcammann/airlock/internal/policy"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"
	ctrladmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	// InjectionEnabledAnnotation enables sidecar injection for a Pod.
	InjectionEnabledAnnotation = controlwebhook.InjectionEnabledAnnotation
	// InjectionWorkloadAnnotation selects the Airlock workload for a Pod.
	InjectionWorkloadAnnotation = controlwebhook.InjectionWorkloadAnnotation
	// InjectionEnvoyModeAnnotation selects managed or existing Envoy mode.
	InjectionEnvoyModeAnnotation = controlwebhook.InjectionEnvoyModeAnnotation
	// EnvoyModeManaged injects an Airlock-managed Envoy container.
	EnvoyModeManaged = controlwebhook.EnvoyModeManaged
	// EnvoyModeExisting expects an existing Envoy sidecar.
	EnvoyModeExisting = controlwebhook.EnvoyModeExisting
	// ProxyWorkerLabel labels injected proxy-worker containers.
	ProxyWorkerLabel = controlwebhook.ProxyWorkerLabel
	// InjectionWebhookPath is the Kubernetes admission path for Pod mutation.
	InjectionWebhookPath = controlwebhook.MutationPath
)

// InjectionOptions configures admission webhook mutation.
type InjectionOptions = controlwebhook.InjectionOptions

type admissionReview = controlwebhook.AdmissionReview
type admissionRequest = controlwebhook.AdmissionRequest
type admissionKind = controlwebhook.AdmissionKind
type jsonPatchOperation = controlwebhook.JSONPatchOperation

// NewInjectionWebhookHandler creates the Pod injection admission handler.
func NewInjectionWebhookHandler(server *Server, opts InjectionOptions) http.Handler {
	return controlwebhook.NewHandler(injectionPolicyResolver{server: server}, opts)
}

// NewInjectionAdmissionHandler creates the controller-runtime Pod injection admission handler.
func NewInjectionAdmissionHandler(server *Server, opts InjectionOptions) ctrladmission.Handler {
	return controlwebhook.NewAdmissionHandler(injectionPolicyResolver{server: server}, opts)
}

// RegisterInjectionWebhook registers the Pod injection webhook with a controller-runtime webhook server.
func RegisterInjectionWebhook(webhookServer ctrlwebhook.Server, server *Server, opts InjectionOptions) {
	controlwebhook.RegisterAdmissionWebhook(webhookServer, injectionPolicyResolver{server: server}, opts)
}

type injectionPolicyResolver struct {
	server *Server
}

// GetPolicy returns the compiled policy for an injected workload.
func (r injectionPolicyResolver) GetPolicy(workloadIdentity string) (policy.CompiledPolicy, bool) {
	return r.server.getPolicy(workloadIdentity)
}
