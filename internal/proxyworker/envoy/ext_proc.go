package envoy

import (
	"context"
	"fmt"
	"strings"

	airlockv1 "github.com/marcammann/airlock/api/v1alpha1"
	"github.com/marcammann/airlock/internal/proxyworker/egress"
	workersecrets "github.com/marcammann/airlock/internal/proxyworker/secrets"
	workertel "github.com/marcammann/airlock/internal/proxyworker/telemetry"
	globalotel "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// CompiledPolicy is the policy format evaluated by Envoy ext_proc.
type CompiledPolicy = airlockv1.CompiledPolicy

// ExtProcDecision describes the response Airlock should return to Envoy ext_proc.
type ExtProcDecision struct {
	Continue  bool
	Mutations []egress.Header
	Deny      bool
	Status    uint16
	Body      string
	Details   string
}

// Equal reports whether two ext_proc decisions are identical.
func (d ExtProcDecision) Equal(other ExtProcDecision) bool {
	if d.Continue != other.Continue || d.Deny != other.Deny || d.Status != other.Status || d.Body != other.Body || d.Details != other.Details {
		return false
	}
	if len(d.Mutations) != len(other.Mutations) {
		return false
	}
	for i := range d.Mutations {
		if d.Mutations[i] != other.Mutations[i] {
			return false
		}
	}
	return true
}

// EvaluateExtProcHeaders evaluates request headers against a policy.
func EvaluateExtProcHeaders(policy CompiledPolicy, requestHeaders []egress.Header, secrets workersecrets.SecretProvider, log *workertel.EventLog) (ExtProcDecision, error) {
	return EvaluateExtProcHeadersWithContext(context.Background(), policy, requestHeaders, secrets, log)
}

// EvaluateExtProcHeadersWithContext evaluates request headers with tracing context.
func EvaluateExtProcHeadersWithContext(ctx context.Context, policy CompiledPolicy, requestHeaders []egress.Header, secrets workersecrets.SecretProvider, log *workertel.EventLog) (ExtProcDecision, error) {
	if log == nil {
		log = workertel.NewEventLog(nil)
	}
	_, span := globalotel.Tracer("github.com/marcammann/airlock/proxyworker").Start(ctx, "airlock.ext_proc.evaluate")
	defer span.End()
	method, ok := egress.HeaderValue(requestHeaders, ":method")
	if !ok {
		method = "UNKNOWN"
	}
	destination, err := egress.DestinationFromHeadersWithMethod(requestHeaders, method)
	if err != nil {
		return ExtProcDecision{}, err
	}
	setExtProcSpanAttributes(span, destination, method, workertel.DecisionNone)
	rule := egress.FindEgressRule(policy, destination)
	if rule == nil {
		setExtProcSpanAttributes(span, destination, method, workertel.DecisionDeny)
		log.Record(workertel.DecisionDeny, egress.FormatDecisionLog("ext_proc request", "denied", policy, nil, method, destination, ""), egress.DecisionFields(method, destination, nil, nil))
		return ExtProcDecision{Deny: true, Status: 403, Body: "egress denied", Details: "airlock_egress_denied"}, nil
	}
	if strings.EqualFold(method, "CONNECT") {
		setExtProcSpanAttributes(span, destination, method, workertel.DecisionAllow)
		log.Record(workertel.DecisionAllow, egress.FormatDecisionLog("ext_proc CONNECT", "allowed", policy, rule, "", destination, ""), egress.DecisionFields(method, destination, rule, nil))
		return ExtProcDecision{Continue: true}, nil
	}

	var redactor egress.Redactor
	rewritten := append([]egress.Header(nil), requestHeaders...)
	if err := egress.ApplyRewrites(&rewritten, rule.Rewrites, secrets, &redactor); err != nil {
		setExtProcSpanAttributes(span, destination, method, workertel.DecisionSecretError)
		log.Record(workertel.DecisionSecretError, egress.FormatDecisionLog("ext_proc request", "denied", policy, rule, method, destination, fmt.Sprintf("dependency=secret error=%v", err)), egress.DecisionFields(method, destination, rule, map[string]string{"dependency": "secret", "reason": "secret_dependency_failed"}))
		return ExtProcDecision{}, err
	}
	var mutations []egress.Header
	for _, rewrite := range rule.Rewrites {
		if value, ok := egress.HeaderValue(rewritten, rewrite.Name); ok {
			mutations = append(mutations, egress.Header{Name: rewrite.Name, Value: value})
		}
	}
	setExtProcSpanAttributes(span, destination, method, workertel.DecisionAllow)
	log.Record(workertel.DecisionAllow, redactor.Redact(egress.FormatDecisionLog("ext_proc request", "allowed", policy, rule, method, destination, fmt.Sprintf("mutations=%+v", mutations))), egress.DecisionFields(method, destination, rule, nil))
	return ExtProcDecision{Continue: true, Mutations: mutations}, nil
}

func setExtProcSpanAttributes(span traceSpan, destination egress.Destination, method string, decision workertel.DecisionKind) {
	if span == nil || !span.IsRecording() {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("egress.host", destination.Host),
		attribute.Int("egress.port", int(destination.Port)),
		attribute.String("egress.scheme", destination.Scheme),
		attribute.String("http.request.method", method),
	}
	if decision != workertel.DecisionNone {
		attrs = append(attrs, attribute.String("decision", string(decision)))
	}
	span.SetAttributes(attrs...)
}

type traceSpan interface {
	IsRecording() bool
	SetAttributes(...attribute.KeyValue)
}
