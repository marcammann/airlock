package names

import (
	"strings"
	"testing"
)

func TestDNSLabelPartNormalizesNameSegment(t *testing.T) {
	got := DNSLabelPart(" Demo__Code Agent!! ")
	if got != "demo-code-agent" {
		t.Fatalf("DNSLabelPart() = %q, want demo-code-agent", got)
	}
}

func TestAirlockClusterResourceNameIsStableAndBounded(t *testing.T) {
	namespace := strings.Repeat("namespace-", 20)
	name := strings.Repeat("workload-", 20)

	first := AirlockClusterResourceName(namespace, name)
	second := AirlockClusterResourceName(namespace, name)
	if first != second {
		t.Fatalf("AirlockClusterResourceName() = %q then %q, want stable value", first, second)
	}
	if len(first) > 253 {
		t.Fatalf("AirlockClusterResourceName() length = %d, want <= 253", len(first))
	}
	if !strings.HasPrefix(first, "airlock-namespace") {
		t.Fatalf("AirlockClusterResourceName() = %q, want airlock prefix", first)
	}
}
