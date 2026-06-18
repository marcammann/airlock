package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPolicyStoreNormalizesPolicyResources(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	workloadPath := filepath.Join(dir, "workload.yaml")
	if err := os.WriteFile(policyPath, []byte(`apiVersion: airlock.dev/v1alpha1
kind: AirlockPolicy
metadata:
  name: openai-api
  namespace: airlock-system
spec:
  egress:
    - name: openai-api
      scheme: HTTPS
      host: API.EXAMPLE.TEST
      port: 443
      rewrites:
        - target: header
          name: Authorization
          valueTemplate: "Bearer {{secret}}"
          valueFrom:
            provider: env
            name: test-token
            env: AIRLOCK_TEST_TOKEN
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workloadPath, []byte(`apiVersion: airlock.dev/v1alpha1
kind: AirlockWorkload
metadata:
  name: code-agent
  namespace: airlock-system
spec:
  workload:
    spiffeId: spiffe://airlock.local/ns/demo/sa/code-agent/component/airlock-proxy-worker
    namespace: demo
    serviceAccount: code-agent
  policyRefs:
    - name: openai-api
`), 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := LoadPolicyStore([]string{policyPath}, []string{workloadPath})
	if err != nil {
		t.Fatal(err)
	}

	policies := store.AirlockPolicies()
	if got := policies[0].Spec.Egress[0].Scheme; got != "https" {
		t.Fatalf("stored policy scheme = %q, want https", got)
	}
	if got := policies[0].Spec.Egress[0].Host; got != "api.example.test" {
		t.Fatalf("stored policy host = %q, want api.example.test", got)
	}
	compiled := store.Policies()
	if got := compiled[0].Egress[0].Scheme; got != "https" {
		t.Fatalf("compiled policy scheme = %q, want https", got)
	}
	if got := compiled[0].Egress[0].Host; got != "api.example.test" {
		t.Fatalf("compiled policy host = %q, want api.example.test", got)
	}
}
