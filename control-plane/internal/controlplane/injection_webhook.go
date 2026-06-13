package controlplane

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	InjectionEnabledAnnotation   = "airlock.dev/enabled"
	InjectionPolicyAnnotation    = "airlock.dev/policy"
	InjectionEnvoyModeAnnotation = "airlock.dev/envoy-mode"
	EnvoyModeManaged             = "managed"
	EnvoyModeExisting            = "existing"
	ProxyWorkerLabel             = "airlock.dev/proxy-worker"
)

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

func NewInjectionWebhookHandler(server *Server, opts InjectionOptions) http.Handler {
	opts = opts.withDefaults()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mutate/v1/pods", func(w http.ResponseWriter, r *http.Request) {
		handlePodMutation(w, r, server, opts)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	return mux
}

type admissionReview struct {
	APIVersion string             `json:"apiVersion,omitempty"`
	Kind       string             `json:"kind,omitempty"`
	Request    *admissionRequest  `json:"request,omitempty"`
	Response   *admissionResponse `json:"response,omitempty"`
}

type admissionRequest struct {
	UID       string          `json:"uid"`
	Kind      admissionKind   `json:"kind,omitempty"`
	Namespace string          `json:"namespace,omitempty"`
	Object    json.RawMessage `json:"object,omitempty"`
}

type admissionKind struct {
	Group   string `json:"group,omitempty"`
	Version string `json:"version,omitempty"`
	Kind    string `json:"kind,omitempty"`
}

type admissionResponse struct {
	UID       string           `json:"uid,omitempty"`
	Allowed   bool             `json:"allowed"`
	Status    *admissionStatus `json:"status,omitempty"`
	Patch     string           `json:"patch,omitempty"`
	PatchType string           `json:"patchType,omitempty"`
}

type admissionStatus struct {
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

type jsonPatchOperation struct {
	Operation string `json:"op"`
	Path      string `json:"path"`
	Value     any    `json:"value,omitempty"`
}

func handlePodMutation(w http.ResponseWriter, r *http.Request, server *Server, opts InjectionOptions) {
	var review admissionReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		writeAdmissionReview(w, review, admissionResponse{Allowed: false, Status: &admissionStatus{Message: "decode AdmissionReview: " + err.Error()}})
		return
	}
	if review.Request == nil {
		writeAdmissionReview(w, review, admissionResponse{Allowed: false, Status: &admissionStatus{Message: "AdmissionReview request is required"}})
		return
	}

	response := mutatePod(review.Request, server, opts)
	writeAdmissionReview(w, review, response)
}

func mutatePod(request *admissionRequest, server *Server, opts InjectionOptions) admissionResponse {
	response := admissionResponse{UID: request.UID, Allowed: true}

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
	compiled, ok := server.getPolicy(workloadIdentity)
	if !ok {
		return denyAdmission(request.UID, "no Airlock policy for workload identity "+workloadIdentity)
	}
	if policyName := strings.TrimSpace(pod.Metadata.Annotations[InjectionPolicyAnnotation]); policyName != "" && policyName != compiled.PolicyName {
		return denyAdmission(request.UID, fmt.Sprintf("annotation %s=%q does not match policy %q for workload identity", InjectionPolicyAnnotation, policyName, compiled.PolicyName))
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

func denyAdmission(uid string, message string) admissionResponse {
	return admissionResponse{
		UID:     uid,
		Allowed: false,
		Status:  &admissionStatus{Message: message},
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

func injectionPatch(pod podForMutation, opts InjectionOptions, workloadIdentity string, envoyMode string) []jsonPatchOperation {
	var patch []jsonPatchOperation
	if pod.Metadata.Labels == nil {
		patch = append(patch, jsonPatchOperation{Operation: "add", Path: "/metadata/labels", Value: map[string]string{}})
	}
	if pod.Metadata.Labels[ProxyWorkerLabel] != "true" {
		patch = append(patch, jsonPatchOperation{Operation: "add", Path: "/metadata/labels/" + jsonPointerEscape(ProxyWorkerLabel), Value: "true"})
	}

	if envoyMode == EnvoyModeManaged {
		patch = append(patch, managedProxyEnvPatches(pod.Spec.Containers, opts)...)
	}
	if envoyMode == EnvoyModeManaged && !hasContainer(pod.Spec.Containers, "envoy") {
		patch = append(patch, jsonPatchOperation{Operation: "add", Path: "/spec/containers/-", Value: envoyContainer(opts)})
	}
	patch = append(patch, jsonPatchOperation{Operation: "add", Path: "/spec/containers/-", Value: proxyWorkerContainer(opts, workloadIdentity)})

	if !hasVolume(pod.Spec.Volumes, "spire-agent-socket") {
		volume := map[string]any{
			"name": "spire-agent-socket",
			"hostPath": map[string]any{
				"path": "/run/spire/agent-sockets",
				"type": "Directory",
			},
		}
		if pod.Spec.Volumes == nil {
			patch = append(patch, jsonPatchOperation{Operation: "add", Path: "/spec/volumes", Value: []any{volume}})
		} else {
			patch = append(patch, jsonPatchOperation{Operation: "add", Path: "/spec/volumes/-", Value: volume})
		}
	}

	return patch
}

func managedProxyEnvPatches(containers []podContainer, opts InjectionOptions) []jsonPatchOperation {
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

	var patch []jsonPatchOperation
	for i, container := range containers {
		if container.Name == "envoy" || container.Name == "proxy-worker" {
			continue
		}
		if len(container.Env) == 0 {
			patch = append(patch, jsonPatchOperation{
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
			patch = append(patch, jsonPatchOperation{
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
			"--control-plane-auth",
			"spiffe",
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

func writeAdmissionReview(w http.ResponseWriter, review admissionReview, response admissionResponse) {
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
