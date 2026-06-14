package proxyworker

import (
	"fmt"
	"strings"
)

const Redacted = "[REDACTED]"

type Redactor struct {
	values []string
}

func (r *Redactor) Add(value string) {
	if value == "" {
		return
	}
	for _, known := range r.values {
		if known == value {
			return
		}
	}
	r.values = append(r.values, value)
}

func (r *Redactor) Redact(input string) string {
	out := input
	for _, value := range r.values {
		out = strings.ReplaceAll(out, value, Redacted)
	}
	return out
}

func FindEgressRule(policy CompiledPolicy, destination Destination) *EgressRule {
	for i := range policy.Egress {
		rule := &policy.Egress[i]
		if strings.EqualFold(rule.Host, destination.Host) &&
			ruleSchemeMatches(*rule, destination) &&
			rulePortMatches(*rule, destination) {
			return rule
		}
	}
	return nil
}

func ruleSchemeMatches(rule EgressRule, destination Destination) bool {
	return rule.Scheme == "" || strings.EqualFold(rule.Scheme, destination.Scheme)
}

func rulePortMatches(rule EgressRule, destination Destination) bool {
	return rule.Port == 0 || rule.Port == uint32(destination.Port)
}

func ApplyRewrites(headers *[]Header, rewrites []RewriteRule, secrets SecretProvider, redactor *Redactor) error {
	for _, rewrite := range rewrites {
		if rewrite.Target != "header" {
			return fmt.Errorf("unsupported rewrite target %q", rewrite.Target)
		}
		secret, err := secrets.Resolve(rewrite.ValueFrom)
		if err != nil {
			return err
		}
		redactor.Add(secret)
		value := secret
		if rewrite.ValueTemplate != "" {
			value = strings.ReplaceAll(rewrite.ValueTemplate, "{{secret}}", secret)
		}
		setHeader(headers, rewrite.Name, value)
	}
	return nil
}
