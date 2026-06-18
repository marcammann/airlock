// Package webhook contains the Kubernetes admission webhook used to inject
// Airlock proxy workers into opted-in pods.
package webhook

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/marcammann/airlock/internal/policy"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"
	ctrladmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	// InjectionEnabledAnnotation enables Airlock sidecar injection for a Pod.
	InjectionEnabledAnnotation = "airlock.dev/enabled"
	// InjectionWorkloadAnnotation selects the Airlock workload for a Pod.
	InjectionWorkloadAnnotation = "airlock.dev/workload"
	// InjectionEnvoyModeAnnotation selects managed or existing Envoy mode for injected Pods.
	InjectionEnvoyModeAnnotation = "airlock.dev/envoy-mode"
	// EnvoyModeManaged injects an Airlock-managed Envoy sidecar.
	EnvoyModeManaged = "managed"
	// EnvoyModeExisting expects a pre-existing Envoy sidecar.
	EnvoyModeExisting = "existing"
	// ProxyWorkerLabel identifies Pods with injected Airlock proxy workers.
	ProxyWorkerLabel = "airlock.dev/proxy-worker"
	// MutationPath is the Kubernetes admission path for Airlock Pod mutation.
	MutationPath = "/mutate/v1/pods"
)

// InjectionOptions configures the pod mutation webhook.
type InjectionOptions struct {
	TrustDomain          string
	ProxyWorkerImage     string
	EnvoyImage           string
	ControlPlaneURL      string
	ControlPlaneServerID string
	SPIFFESocket         string
	EnvoyListenAddress   string
	EnvoyListenPort      int
	ExtProcAddress       string
	ExtProcPort          int
	UpstreamHost         string
	UpstreamPort         int
	WebhookClientCAs     *x509.CertPool
}

// PolicyResolver resolves the compiled Airlock policy for a workload identity.
type PolicyResolver interface {
	GetPolicy(workloadIdentity string) (policy.CompiledPolicy, bool)
}

func (o InjectionOptions) withDefaults() InjectionOptions {
	if strings.TrimSpace(o.TrustDomain) == "" {
		o.TrustDomain = "airlock.local"
	}
	if strings.TrimSpace(o.ProxyWorkerImage) == "" {
		o.ProxyWorkerImage = "airlock-proxy-worker:dev"
	}
	if strings.TrimSpace(o.EnvoyImage) == "" {
		o.EnvoyImage = "envoyproxy/envoy:v1.31.0"
	}
	if strings.TrimSpace(o.ControlPlaneURL) == "" {
		o.ControlPlaneURL = "https://airlock-control-plane.airlock-system.svc.cluster.local:8443"
	}
	if strings.TrimSpace(o.ControlPlaneServerID) == "" {
		o.ControlPlaneServerID = "spiffe://" + o.TrustDomain + "/ns/airlock-system/sa/airlock-control-plane"
	}
	if strings.TrimSpace(o.SPIFFESocket) == "" {
		o.SPIFFESocket = "unix:///run/spire/agent-sockets/spire-agent.sock"
	}
	if strings.TrimSpace(o.EnvoyListenAddress) == "" {
		o.EnvoyListenAddress = "127.0.0.1"
	}
	if o.EnvoyListenPort == 0 {
		o.EnvoyListenPort = 10000
	}
	if strings.TrimSpace(o.ExtProcAddress) == "" {
		o.ExtProcAddress = "127.0.0.1"
	}
	if o.ExtProcPort == 0 {
		o.ExtProcPort = 50051
	}
	if strings.TrimSpace(o.UpstreamHost) == "" {
		o.UpstreamHost = "echo-upstream.demo.svc.cluster.local"
	}
	if o.UpstreamPort == 0 {
		o.UpstreamPort = 8080
	}
	return o
}

// NewHandler returns an HTTP handler for the Airlock pod mutation webhook.
func NewHandler(resolver PolicyResolver, opts InjectionOptions) http.Handler {
	opts = opts.withDefaults()
	r := chi.NewRouter()
	r.Post(MutationPath, func(w http.ResponseWriter, r *http.Request) {
		handlePodMutation(w, r, resolver, opts)
	})
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	return r
}

// NewAdmissionHandler returns a controller-runtime admission handler for Pod mutation.
func NewAdmissionHandler(resolver PolicyResolver, opts InjectionOptions) ctrladmission.Handler {
	return podMutationAdmissionHandler{
		resolver: resolver,
		opts:     opts.withDefaults(),
	}
}

// NewAdmissionWebhook returns a controller-runtime admission webhook HTTP handler.
func NewAdmissionWebhook(resolver PolicyResolver, opts InjectionOptions) http.Handler {
	return &ctrladmission.Webhook{Handler: NewAdmissionHandler(resolver, opts)}
}

// RegisterAdmissionWebhook registers the Airlock Pod mutating webhook on a controller-runtime webhook server.
func RegisterAdmissionWebhook(server ctrlwebhook.Server, resolver PolicyResolver, opts InjectionOptions) {
	server.Register(MutationPath, NewAdmissionWebhook(resolver, opts))
}

type podMutationAdmissionHandler struct {
	resolver PolicyResolver
	opts     InjectionOptions
}

func (h podMutationAdmissionHandler) Handle(_ context.Context, request ctrladmission.Request) ctrladmission.Response {
	if request.Kind.Kind != "Pod" {
		return ctrladmission.Denied("AdmissionReview request kind must be Pod")
	}
	response := mutatePod(&AdmissionRequest{
		UID:       string(request.UID),
		Kind:      AdmissionKind{Group: request.Kind.Group, Version: request.Kind.Version, Kind: request.Kind.Kind},
		Namespace: request.Namespace,
		Object:    request.Object.Raw,
	}, h.resolver, h.opts)
	return toControllerRuntimeAdmissionResponse(response)
}

func toControllerRuntimeAdmissionResponse(response AdmissionResponse) ctrladmission.Response {
	out := ctrladmission.Response{
		AdmissionResponse: admissionv1.AdmissionResponse{
			UID:     types.UID(response.UID),
			Allowed: response.Allowed,
		},
	}
	if response.Status != nil {
		out.Result = &metav1.Status{Message: response.Status.Message}
	}
	if !response.Allowed {
		if out.Result == nil {
			out.Result = &metav1.Status{}
		}
		out.Result.Code = int32(http.StatusForbidden)
		out.Result.Reason = metav1.StatusReasonForbidden
	}
	if response.Patch == "" {
		return out
	}
	patch, err := base64.StdEncoding.DecodeString(response.Patch)
	if err != nil {
		return ctrladmission.Errored(http.StatusInternalServerError, fmt.Errorf("decode JSON patch: %w", err))
	}
	patchType := admissionv1.PatchTypeJSONPatch
	out.Patch = patch
	out.PatchType = &patchType
	return out
}

// AdmissionReview is the Kubernetes admission.k8s.io/v1 AdmissionReview wire shape.
type AdmissionReview struct {
	APIVersion string             `json:"apiVersion,omitempty"`
	Kind       string             `json:"kind,omitempty"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

// AdmissionRequest contains the Kubernetes object under admission review.
type AdmissionRequest struct {
	UID       string          `json:"uid"`
	Kind      AdmissionKind   `json:"kind,omitempty"`
	Namespace string          `json:"namespace,omitempty"`
	Object    json.RawMessage `json:"object,omitempty"`
}

// AdmissionKind identifies the Kubernetes kind under admission review.
type AdmissionKind struct {
	Group   string `json:"group,omitempty"`
	Version string `json:"version,omitempty"`
	Kind    string `json:"kind,omitempty"`
}

// AdmissionResponse contains the admission decision and optional JSON patch.
type AdmissionResponse struct {
	UID       string           `json:"uid,omitempty"`
	Allowed   bool             `json:"allowed"`
	Status    *AdmissionStatus `json:"status,omitempty"`
	Patch     string           `json:"patch,omitempty"`
	PatchType string           `json:"patchType,omitempty"`
}

// AdmissionStatus describes why an admission request was denied.
type AdmissionStatus struct {
	Message string `json:"message,omitempty"`
}

type podForMutation struct {
	Metadata podMetadata `json:"metadata"`
	Spec     podSpec     `json:"spec"`
}

type podMetadata struct {
	Name        string            `json:"name,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type podSpec struct {
	ServiceAccountName string         `json:"serviceAccountName,omitempty"`
	Containers         []podContainer `json:"containers,omitempty"`
	Volumes            []namedObject  `json:"volumes,omitempty"`
}

type podContainer struct {
	Name string        `json:"name"`
	Env  []namedObject `json:"env,omitempty"`
}

type namedObject struct {
	Name string `json:"name"`
}

// JSONPatchOperation is one RFC 6902 patch operation returned to Kubernetes.
type JSONPatchOperation struct {
	Operation string `json:"op"`
	Path      string `json:"path"`
	Value     any    `json:"value,omitempty"`
}

func handlePodMutation(w http.ResponseWriter, r *http.Request, resolver PolicyResolver, opts InjectionOptions) {
	if opts.WebhookClientCAs != nil {
		if err := verifyWebhookClientCertificate(r, opts.WebhookClientCAs); err != nil {
			writeAdmissionReview(w, AdmissionReview{}, denyAdmission("", "verify webhook client certificate: "+err.Error()))
			return
		}
	}

	var review AdmissionReview
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&review); err != nil {
		writeAdmissionReview(w, review, AdmissionResponse{Allowed: false, Status: &AdmissionStatus{Message: "decode AdmissionReview: " + err.Error()}})
		return
	}
	if review.Request == nil {
		writeAdmissionReview(w, review, AdmissionResponse{Allowed: false, Status: &AdmissionStatus{Message: "AdmissionReview request is required"}})
		return
	}
	if review.APIVersion != "admission.k8s.io/v1" {
		writeAdmissionReview(w, review, denyAdmission(review.Request.UID, "AdmissionReview apiVersion must be admission.k8s.io/v1"))
		return
	}
	if review.Request.Kind.Kind != "Pod" {
		writeAdmissionReview(w, review, denyAdmission(review.Request.UID, "AdmissionReview request kind must be Pod"))
		return
	}

	response := mutatePod(review.Request, resolver, opts)
	writeAdmissionReview(w, review, response)
}

func verifyWebhookClientCertificate(r *http.Request, roots *x509.CertPool) error {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return fmt.Errorf("client certificate is required")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range r.TLS.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err := r.TLS.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

func mutatePod(request *AdmissionRequest, resolver PolicyResolver, opts InjectionOptions) AdmissionResponse {
	response := AdmissionResponse{UID: request.UID, Allowed: true}

	var pod podForMutation
	if err := json.Unmarshal(request.Object, &pod); err != nil {
		return denyAdmission(request.UID, "decode Pod: "+err.Error())
	}
	if !annotationEnabled(pod.Metadata.Annotations[InjectionEnabledAnnotation]) {
		return response
	}
	if hasContainer(pod.Spec.Containers, "proxy-worker") {
		return response
	}
	envoyMode, err := injectionEnvoyMode(pod.Metadata.Annotations[InjectionEnvoyModeAnnotation])
	if err != nil {
		return denyAdmission(request.UID, err.Error())
	}
	if len(pod.Spec.Containers) == 0 {
		return denyAdmission(request.UID, "pod must have at least one app container")
	}

	namespace := strings.TrimSpace(pod.Metadata.Namespace)
	if namespace == "" {
		namespace = strings.TrimSpace(request.Namespace)
	}
	if namespace == "" {
		return denyAdmission(request.UID, "pod namespace is required")
	}
	serviceAccountName := strings.TrimSpace(pod.Spec.ServiceAccountName)
	if serviceAccountName == "" {
		serviceAccountName = "default"
	}

	workloadIdentity := fmt.Sprintf("spiffe://%s/ns/%s/sa/%s/component/airlock-proxy-worker", opts.TrustDomain, namespace, serviceAccountName)
	compiled, ok := resolver.GetPolicy(workloadIdentity)
	if !ok {
		return denyAdmission(request.UID, "no Airlock workload for workload identity "+workloadIdentity)
	}
	if workloadName := strings.TrimSpace(pod.Metadata.Annotations[InjectionWorkloadAnnotation]); workloadName != "" && workloadName != compiled.PolicyName {
		return denyAdmission(request.UID, fmt.Sprintf("annotation %s=%q does not match AirlockWorkload %q for workload identity", InjectionWorkloadAnnotation, workloadName, compiled.PolicyName))
	}

	patch := injectionPatch(pod, opts, workloadIdentity, envoyMode)
	if len(patch) == 0 {
		return response
	}
	data, err := json.Marshal(patch)
	if err != nil {
		return denyAdmission(request.UID, "encode JSON patch: "+err.Error())
	}
	response.PatchType = "JSONPatch"
	response.Patch = base64.StdEncoding.EncodeToString(data)
	return response
}

func denyAdmission(uid string, message string) AdmissionResponse {
	return AdmissionResponse{
		UID:     uid,
		Allowed: false,
		Status:  &AdmissionStatus{Message: message},
	}
}

func injectionEnvoyMode(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return EnvoyModeManaged, nil
	}
	switch value {
	case EnvoyModeManaged, EnvoyModeExisting:
		return value, nil
	default:
		return "", fmt.Errorf("unsupported %s=%q; supported values are %q and %q", InjectionEnvoyModeAnnotation, value, EnvoyModeManaged, EnvoyModeExisting)
	}
}

func annotationEnabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "t", "true", "y", "yes", "on":
		return true
	default:
		return false
	}
}

func hasContainer(containers []podContainer, name string) bool {
	for _, container := range containers {
		if container.Name == name {
			return true
		}
	}
	return false
}

func hasVolume(volumes []namedObject, name string) bool {
	for _, volume := range volumes {
		if volume.Name == name {
			return true
		}
	}
	return false
}

func injectionPatch(pod podForMutation, opts InjectionOptions, workloadIdentity string, envoyMode string) []JSONPatchOperation {
	var patch []JSONPatchOperation
	if pod.Metadata.Labels == nil {
		patch = append(patch, JSONPatchOperation{Operation: "add", Path: "/metadata/labels", Value: map[string]string{}})
	}
	if pod.Metadata.Labels[ProxyWorkerLabel] != "true" {
		patch = append(patch, JSONPatchOperation{Operation: "add", Path: "/metadata/labels/" + jsonPointerEscape(ProxyWorkerLabel), Value: "true"})
	}

	if envoyMode == EnvoyModeManaged {
		patch = append(patch, managedProxyEnvPatches(pod.Spec.Containers, opts)...)
	}
	if envoyMode == EnvoyModeManaged && !hasContainer(pod.Spec.Containers, "envoy") {
		patch = append(patch, JSONPatchOperation{Operation: "add", Path: "/spec/containers/-", Value: envoyContainer(opts)})
	}
	patch = append(patch, JSONPatchOperation{Operation: "add", Path: "/spec/containers/-", Value: proxyWorkerContainer(opts, workloadIdentity)})

	if !hasVolume(pod.Spec.Volumes, "spire-agent-socket") {
		volume := map[string]any{
			"name": "spire-agent-socket",
			"hostPath": map[string]any{
				"path": "/run/spire/agent-sockets",
				"type": "Directory",
			},
		}
		if pod.Spec.Volumes == nil {
			patch = append(patch, JSONPatchOperation{Operation: "add", Path: "/spec/volumes", Value: []any{volume}})
		} else {
			patch = append(patch, JSONPatchOperation{Operation: "add", Path: "/spec/volumes/-", Value: volume})
		}
	}

	return patch
}

func managedProxyEnvPatches(containers []podContainer, opts InjectionOptions) []JSONPatchOperation {
	proxyURL := fmt.Sprintf("http://%s:%d", opts.EnvoyListenAddress, opts.EnvoyListenPort)
	noProxy := "127.0.0.1,localhost,::1"
	envVars := []map[string]any{
		{"name": "HTTP_PROXY", "value": proxyURL},
		{"name": "HTTPS_PROXY", "value": proxyURL},
		{"name": "http_proxy", "value": proxyURL},
		{"name": "https_proxy", "value": proxyURL},
		{"name": "NO_PROXY", "value": noProxy},
		{"name": "no_proxy", "value": noProxy},
	}

	var patch []JSONPatchOperation
	for i, container := range containers {
		if container.Name == "envoy" || container.Name == "proxy-worker" {
			continue
		}
		if len(container.Env) == 0 {
			patch = append(patch, JSONPatchOperation{
				Operation: "add",
				Path:      fmt.Sprintf("/spec/containers/%d/env", i),
				Value:     envVars,
			})
			continue
		}
		for _, envVar := range envVars {
			if hasEnvVar(container.Env, envVar["name"].(string)) {
				continue
			}
			patch = append(patch, JSONPatchOperation{
				Operation: "add",
				Path:      fmt.Sprintf("/spec/containers/%d/env/-", i),
				Value:     envVar,
			})
		}
	}
	return patch
}

func hasEnvVar(env []namedObject, name string) bool {
	for _, item := range env {
		if item.Name == name {
			return true
		}
	}
	return false
}

func envoyContainer(opts InjectionOptions) map[string]any {
	return map[string]any{
		"name":  "envoy",
		"image": opts.EnvoyImage,
		"args": []string{
			"--config-yaml",
			envoyBootstrapYAML(opts),
			"--log-level",
			"info",
		},
		"ports": []map[string]any{{
			"name":          "envoy-http",
			"containerPort": opts.EnvoyListenPort,
		}},
	}
}

func proxyWorkerContainer(opts InjectionOptions, workloadIdentity string) map[string]any {
	return map[string]any{
		"name":            "proxy-worker",
		"image":           opts.ProxyWorkerImage,
		"imagePullPolicy": "IfNotPresent",
		"args": []string{
			"--proxy",
			fmt.Sprintf("http:envoy@%s:%d", opts.ExtProcAddress, opts.ExtProcPort),
			"--control-plane-url",
			opts.ControlPlaneURL,
			"--control-plane-server-id",
			opts.ControlPlaneServerID,
			"--workload-identity",
			workloadIdentity,
			"--spiffe-socket",
			opts.SPIFFESocket,
		},
		"ports": []map[string]any{{
			"name":          "ext-proc",
			"containerPort": opts.ExtProcPort,
		}},
		"env": []map[string]any{{
			"name": "POD_IP",
			"valueFrom": map[string]any{
				"fieldRef": map[string]any{
					"fieldPath": "status.podIP",
				},
			},
		}},
		"volumeMounts": []map[string]any{{
			"name":      "spire-agent-socket",
			"mountPath": "/run/spire/agent-sockets",
			"readOnly":  true,
		}},
	}
}

func envoyBootstrapYAML(opts InjectionOptions) string {
	return fmt.Sprintf(`static_resources:
  listeners:
    - name: airlock_egress
      address:
        socket_address:
          address: %s
          port_value: %d
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: airlock_egress
                route_config:
                  name: airlock_egress_route
                  virtual_hosts:
                    - name: airlock
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: airlock_upstream
                http_filters:
                  - name: envoy.filters.http.ext_proc
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor
                      failure_mode_allow: false
                      grpc_service:
                        envoy_grpc:
                          cluster_name: airlock_ext_proc
                        timeout: 2s
                      processing_mode:
                        request_header_mode: SEND
                        response_header_mode: SKIP
                        request_body_mode: NONE
                        response_body_mode: NONE
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: airlock_ext_proc
      type: STRICT_DNS
      connect_timeout: 1s
      http2_protocol_options: {}
      load_assignment:
        cluster_name: airlock_ext_proc
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: %s
                      port_value: %d
    - name: airlock_upstream
      type: STRICT_DNS
      dns_lookup_family: V4_ONLY
      connect_timeout: 1s
      load_assignment:
        cluster_name: airlock_upstream
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: %s
                      port_value: %d
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9901
`, opts.EnvoyListenAddress, opts.EnvoyListenPort, opts.ExtProcAddress, opts.ExtProcPort, opts.UpstreamHost, opts.UpstreamPort)
}

func jsonPointerEscape(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}

func writeAdmissionReview(w http.ResponseWriter, review AdmissionReview, response AdmissionResponse) {
	if review.APIVersion == "" {
		review.APIVersion = "admission.k8s.io/v1"
	}
	if review.Kind == "" {
		review.Kind = "AdmissionReview"
	}
	review.Request = nil
	review.Response = &response
	writeJSON(w, http.StatusOK, review)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Error("write webhook JSON response failed", "error", err)
	}
}
