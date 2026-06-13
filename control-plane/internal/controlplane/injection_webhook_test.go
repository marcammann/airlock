package controlplane

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestInjectionWebhookInjectsEnvoyAndProxyWorker(t *testing.T) {
	server := testInjectionServer(t)
	review := admissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: &admissionRequest{
			UID:       "test-uid",
			Namespace: "demo",
			Object: mustRawJSON(t, map[string]any{
				"metadata": map[string]any{
					"name":      "code-agent-injected",
					"namespace": "demo",
					"annotations": map[string]string{
						InjectionEnabledAnnotation: "true",
						InjectionPolicyAnnotation:  "code-agent",
					},
				},
				"spec": map[string]any{
					"serviceAccountName": "code-agent",
					"containers": []map[string]any{{
						"name":  "app",
						"image": "curlimages/curl:8.10.1",
					}},
				},
			}),
		},
	}

	response := postAdmissionReview(t, server, review)
	if !response.Response.Allowed {
		t.Fatalf("allowed = false, status = %#v", response.Response.Status)
	}
	if response.Response.PatchType != "JSONPatch" {
		t.Fatalf("patchType = %q, want JSONPatch", response.Response.PatchType)
	}

	var patch []jsonPatchOperation
	data, err := base64.StdEncoding.DecodeString(response.Response.Patch)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &patch); err != nil {
		t.Fatal(err)
	}

	if !patchContainsPath(patch, "/metadata/labels/airlock.dev~1proxy-worker") {
		t.Fatalf("patch does not add proxy-worker label: %#v", patch)
	}
	if !patchAddsContainer(patch, "envoy") {
		t.Fatalf("patch does not add envoy container: %#v", patch)
	}
	if !patchAddsContainer(patch, "proxy-worker") {
		t.Fatalf("patch does not add proxy-worker container: %#v", patch)
	}
	if !patchAddsVolume(patch, "spire-agent-socket") {
		t.Fatalf("patch does not add SPIRE socket volume: %#v", patch)
	}
	if !patchAddsEnvVar(patch, 0, "http_proxy", "http://127.0.0.1:10000") {
		t.Fatalf("patch does not add app http_proxy env var: %#v", patch)
	}
	if !patchAddsEnvVar(patch, 0, "https_proxy", "http://127.0.0.1:10000") {
		t.Fatalf("patch does not add app https_proxy env var: %#v", patch)
	}
	if !patchAddsEnvVar(patch, 0, "NO_PROXY", "127.0.0.1,localhost,::1") {
		t.Fatalf("patch does not add app NO_PROXY env var: %#v", patch)
	}
}

func TestInjectionWebhookLeavesUnannotatedPodUntouched(t *testing.T) {
	server := testInjectionServer(t)
	review := admissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: &admissionRequest{
			UID:       "test-uid",
			Namespace: "demo",
			Object: mustRawJSON(t, map[string]any{
				"metadata": map[string]any{"name": "plain"},
				"spec": map[string]any{
					"serviceAccountName": "code-agent",
					"containers": []map[string]any{{
						"name": "app",
					}},
				},
			}),
		},
	}

	response := postAdmissionReview(t, server, review)
	if !response.Response.Allowed {
		t.Fatalf("allowed = false, status = %#v", response.Response.Status)
	}
	if response.Response.Patch != "" {
		t.Fatalf("patch = %q, want empty", response.Response.Patch)
	}
}

func TestInjectionWebhookExistingEnvoyModeInjectsOnlyProxyWorker(t *testing.T) {
	server := testInjectionServer(t)
	review := admissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: &admissionRequest{
			UID:       "test-uid",
			Namespace: "demo",
			Object: mustRawJSON(t, map[string]any{
				"metadata": map[string]any{
					"name":      "code-agent-existing-envoy",
					"namespace": "demo",
					"annotations": map[string]string{
						InjectionEnabledAnnotation:   "true",
						InjectionPolicyAnnotation:    "code-agent",
						InjectionEnvoyModeAnnotation: EnvoyModeExisting,
					},
				},
				"spec": map[string]any{
					"serviceAccountName": "code-agent",
					"containers": []map[string]any{
						{
							"name":  "app",
							"image": "curlimages/curl:8.10.1",
						},
						{
							"name":  "envoy",
							"image": "envoyproxy/envoy:v1.31.0",
						},
					},
				},
			}),
		},
	}

	response := postAdmissionReview(t, server, review)
	if !response.Response.Allowed {
		t.Fatalf("allowed = false, status = %#v", response.Response.Status)
	}

	var patch []jsonPatchOperation
	data, err := base64.StdEncoding.DecodeString(response.Response.Patch)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &patch); err != nil {
		t.Fatal(err)
	}

	if patchAddsContainer(patch, "envoy") {
		t.Fatalf("patch unexpectedly adds envoy container: %#v", patch)
	}
	if !patchAddsContainer(patch, "proxy-worker") {
		t.Fatalf("patch does not add proxy-worker container: %#v", patch)
	}
	if !patchAddsVolume(patch, "spire-agent-socket") {
		t.Fatalf("patch does not add SPIRE socket volume: %#v", patch)
	}
	if patchAddsEnvVar(patch, 0, "http_proxy", "http://127.0.0.1:10000") {
		t.Fatalf("existing envoy mode unexpectedly adds proxy env vars: %#v", patch)
	}
}

func TestInjectionWebhookDeniesUnsupportedEnvoyMode(t *testing.T) {
	server := testInjectionServer(t)
	review := admissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: &admissionRequest{
			UID:       "test-uid",
			Namespace: "demo",
			Object: mustRawJSON(t, map[string]any{
				"metadata": map[string]any{
					"name": "bad-envoy-mode",
					"annotations": map[string]string{
						InjectionEnabledAnnotation:   "true",
						InjectionEnvoyModeAnnotation: "sideways",
					},
				},
				"spec": map[string]any{
					"serviceAccountName": "code-agent",
					"containers": []map[string]any{{
						"name": "app",
					}},
				},
			}),
		},
	}

	response := postAdmissionReview(t, server, review)
	if response.Response.Allowed {
		t.Fatalf("allowed = true, want false")
	}
	if response.Response.Status == nil || response.Response.Status.Message == "" {
		t.Fatalf("status message is empty")
	}
}

func TestInjectionWebhookDeniesMismatchedPolicyAnnotation(t *testing.T) {
	server := testInjectionServer(t)
	review := admissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: &admissionRequest{
			UID:       "test-uid",
			Namespace: "demo",
			Object: mustRawJSON(t, map[string]any{
				"metadata": map[string]any{
					"name": "bad-policy",
					"annotations": map[string]string{
						InjectionEnabledAnnotation: "true",
						InjectionPolicyAnnotation:  "wrong-policy",
					},
				},
				"spec": map[string]any{
					"serviceAccountName": "code-agent",
					"containers": []map[string]any{{
						"name": "app",
					}},
				},
			}),
		},
	}

	response := postAdmissionReview(t, server, review)
	if response.Response.Allowed {
		t.Fatalf("allowed = true, want false")
	}
	if response.Response.Status == nil || response.Response.Status.Message == "" {
		t.Fatalf("status message is empty")
	}
}

func testInjectionServer(t *testing.T) *Server {
	t.Helper()
	store, err := LoadPolicyStoreWithSecretProviderConfigs(
		[]string{filepath.Join("..", "..", "..", "fixtures", "policies", "valid-vault-provider-ref.yaml")},
		[]string{filepath.Join("..", "..", "..", "fixtures", "secret-provider-configs", "default-vault.yaml")},
	)
	if err != nil {
		t.Fatal(err)
	}
	return NewServerWithAuth(store, AuthModeSPIFFE, "", nil)
}

func postAdmissionReview(t *testing.T, server *Server, review admissionReview) admissionReview {
	t.Helper()
	body, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mutate/v1/pods", bytes.NewReader(body))
	response := httptest.NewRecorder()
	NewInjectionWebhookHandler(server, InjectionOptions{}).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	var out admissionReview
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Response == nil {
		t.Fatalf("AdmissionReview response is nil")
	}
	return out
}

func mustRawJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func patchContainsPath(patch []jsonPatchOperation, path string) bool {
	for _, op := range patch {
		if op.Path == path {
			return true
		}
	}
	return false
}

func patchAddsContainer(patch []jsonPatchOperation, name string) bool {
	for _, op := range patch {
		if op.Path != "/spec/containers/-" {
			continue
		}
		value, ok := op.Value.(map[string]any)
		if ok && value["name"] == name {
			return true
		}
	}
	return false
}

func patchAddsVolume(patch []jsonPatchOperation, name string) bool {
	for _, op := range patch {
		if op.Path != "/spec/volumes" && op.Path != "/spec/volumes/-" {
			continue
		}
		switch value := op.Value.(type) {
		case map[string]any:
			if value["name"] == name {
				return true
			}
		case []any:
			for _, item := range value {
				object, ok := item.(map[string]any)
				if ok && object["name"] == name {
					return true
				}
			}
		}
	}
	return false
}

func patchAddsEnvVar(patch []jsonPatchOperation, containerIndex int, name string, value string) bool {
	envPath := fmt.Sprintf("/spec/containers/%d/env", containerIndex)
	appendPath := envPath + "/-"
	for _, op := range patch {
		switch op.Path {
		case envPath:
			items, ok := op.Value.([]any)
			if !ok {
				continue
			}
			for _, item := range items {
				object, ok := item.(map[string]any)
				if ok && object["name"] == name && object["value"] == value {
					return true
				}
			}
		case appendPath:
			object, ok := op.Value.(map[string]any)
			if ok && object["name"] == name && object["value"] == value {
				return true
			}
		}
	}
	return false
}
