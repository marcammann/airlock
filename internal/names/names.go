package names

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// DNSLabelPart normalizes one human-provided name segment into a DNS-label-safe part.
func DNSLabelPart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var out strings.Builder
	lastDash := false
	for _, ch := range value {
		valid := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
		if valid {
			out.WriteRune(ch)
			lastDash = false
			continue
		}
		if !lastDash {
			out.WriteByte('-')
			lastDash = true
		}
	}
	clean := strings.Trim(out.String(), "-")
	if clean == "" {
		return "default"
	}
	return clean
}

// AirlockClusterResourceName returns the stable name used for Airlock-owned cluster-scoped resources.
func AirlockClusterResourceName(namespace string, name string) string {
	base := "airlock-" + DNSLabelPart(namespace) + "-" + DNSLabelPart(name)
	if len(base) <= 253 {
		return base
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(namespace) + "/" + strings.TrimSpace(name)))
	suffix := hex.EncodeToString(sum[:])[:12]
	prefixLen := 253 - len(suffix) - 1
	prefix := strings.TrimRight(base[:prefixLen], "-")
	if prefix == "" {
		prefix = "airlock"
	}
	return prefix + "-" + suffix
}
