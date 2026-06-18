package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	airlockv1 "github.com/marcammann/airlock/api/v1alpha1"
)

// EventReporter aggregates denied/error decisions and sends them to the control plane.
type EventReporter struct {
	endpoint           string
	client             *http.Client
	proxyID            string
	proxyType          string
	workloadIdentity   string
	workloadName       string
	workloadNamespace  string
	effectiveVersion   string
	sourcePolicyByRule map[string]airlockv1.PolicyRef
	flushInterval      time.Duration
	maxPendingKeys     int

	mu         sync.Mutex
	pending    map[string]*pendingAirlockEvent
	suppressed uint64
	bucket     reportTokenBucket
}

// EventReporterOptions configures control-plane event reporting.
type EventReporterOptions struct {
	Endpoint           string
	ProxyID            string
	ProxyType          string
	WorkloadIdentity   string
	WorkloadName       string
	WorkloadNamespace  string
	EffectiveVersion   string
	SourcePolicyByRule map[string]airlockv1.PolicyRef
	Client             *http.Client
	RatePerSecond      float64
	Burst              int
	FlushInterval      time.Duration
	MaxPendingKeys     int
}

// SourcePolicyByRule indexes source policy references by compiled rule name.
func SourcePolicyByRule(policy airlockv1.CompiledPolicy) map[string]airlockv1.PolicyRef {
	out := map[string]airlockv1.PolicyRef{}
	for _, rule := range policy.Egress {
		if rule.SourcePolicy == nil {
			continue
		}
		out[rule.Name] = *rule.SourcePolicy
	}
	return out
}

type pendingAirlockEvent struct {
	Event eventReportEvent
	Key   string
}

type reportTokenBucket struct {
	Rate   float64
	Burst  int
	Tokens float64
	Last   time.Time
}

// NewEventReporter validates options and creates an event reporter.
func NewEventReporter(opts EventReporterOptions) (*EventReporter, error) {
	if strings.TrimSpace(opts.Endpoint) == "" {
		return nil, fmt.Errorf("event endpoint is required")
	}
	if strings.TrimSpace(opts.ProxyID) == "" {
		return nil, fmt.Errorf("event reporter proxy ID is required")
	}
	if strings.TrimSpace(opts.WorkloadIdentity) == "" {
		return nil, fmt.Errorf("event reporter workload identity is required")
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	rate := opts.RatePerSecond
	if rate <= 0 {
		rate = 1
	}
	burst := opts.Burst
	if burst <= 0 {
		burst = 20
	}
	flushInterval := opts.FlushInterval
	if flushInterval <= 0 {
		flushInterval = time.Second
	}
	maxPendingKeys := opts.MaxPendingKeys
	if maxPendingKeys <= 0 {
		maxPendingKeys = 256
	}
	return &EventReporter{
		endpoint:           strings.TrimSpace(opts.Endpoint),
		client:             client,
		proxyID:            opts.ProxyID,
		proxyType:          opts.ProxyType,
		workloadIdentity:   opts.WorkloadIdentity,
		workloadName:       opts.WorkloadName,
		workloadNamespace:  opts.WorkloadNamespace,
		effectiveVersion:   opts.EffectiveVersion,
		sourcePolicyByRule: opts.SourcePolicyByRule,
		flushInterval:      flushInterval,
		maxPendingKeys:     maxPendingKeys,
		pending:            map[string]*pendingAirlockEvent{},
		bucket: reportTokenBucket{
			Rate:  rate,
			Burst: burst,
		},
	}, nil
}

// UpdatePolicy refreshes policy metadata attached to future events.
func (r *EventReporter) UpdatePolicy(policy airlockv1.CompiledPolicy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.workloadName = policy.PolicyName
	r.workloadNamespace = policy.Workload.Namespace
	r.effectiveVersion = policy.Version
	r.sourcePolicyByRule = SourcePolicyByRule(policy)
}

// RecordDecision queues an aggregated control-plane event for denied/error decisions.
func (r *EventReporter) RecordDecision(event DecisionEvent) {
	airlockEvent, ok := r.eventFromDecision(event)
	if !ok {
		return
	}
	key := eventAggregationKey(airlockEvent)

	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.pending[key]; ok {
		existing.Event.Count++
		existing.Event.LastObservedAt = airlockEvent.LastObservedAt
		existing.Event.ObservedAt = airlockEvent.ObservedAt
		return
	}
	if len(r.pending) >= r.maxPendingKeys {
		r.suppressed++
		return
	}
	r.pending[key] = &pendingAirlockEvent{Event: airlockEvent, Key: key}
}

// Run periodically flushes queued events until the context is canceled.
func (r *EventReporter) Run(ctx context.Context) {
	slog.Info("airlock-proxy-worker event reporting enabled", "proxyID", r.proxyID, "endpoint", r.endpoint, "rate", r.bucket.Rate, "burst", r.bucket.Burst)
	ticker := time.NewTicker(r.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = r.Flush(flushCtx)
			cancel()
			return
		case <-ticker.C:
			if err := r.Flush(ctx); err != nil {
				slog.Error("airlock-proxy-worker event report failed", "proxyID", r.proxyID, "error", err)
			}
		}
	}
}

// Flush sends currently queued events to the control plane.
func (r *EventReporter) Flush(ctx context.Context) error {
	events := r.dequeueReportEvents(time.Now().UTC())
	if len(events) == 0 {
		return nil
	}
	return r.export(ctx, events)
}

func (r *EventReporter) dequeueReportEvents(now time.Time) []eventReportEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	keys := make([]string, 0, len(r.pending))
	for key := range r.pending {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var events []eventReportEvent
	for _, key := range keys {
		if !r.bucket.take(now) {
			break
		}
		pending := r.pending[key]
		events = append(events, pending.Event)
		delete(r.pending, key)
	}
	if r.suppressed > 0 && r.bucket.take(now) {
		events = append(events, r.suppressionEvent(now, r.suppressed))
		r.suppressed = 0
	}
	return events
}

func (b *reportTokenBucket) take(now time.Time) bool {
	if b.Rate <= 0 || b.Burst <= 0 {
		return true
	}
	if b.Last.IsZero() {
		b.Tokens = float64(b.Burst)
	} else {
		b.Tokens += now.Sub(b.Last).Seconds() * b.Rate
		if maxTokens := float64(b.Burst); b.Tokens > maxTokens {
			b.Tokens = maxTokens
		}
	}
	b.Last = now
	if b.Tokens < 1 {
		return false
	}
	b.Tokens--
	return true
}

func (r *EventReporter) eventFromDecision(event DecisionEvent) (eventReportEvent, bool) {
	if event.Decision == DecisionAllow || event.Decision == DecisionNone {
		return eventReportEvent{}, false
	}
	fields := copyDecisionFields(event.Fields)
	eventType := "egress.denied"
	severity := "warning"
	reason := fields["reason"]
	switch event.Decision {
	case DecisionDeny:
	case DecisionSecretError:
		eventType = "secret.resolve_failed"
		severity = "error"
		if reason == "" {
			reason = "secret_dependency_failed"
		}
	case DecisionProxyError:
		eventType = "proxy.error"
		severity = "error"
	default:
		return eventReportEvent{}, false
	}
	if reason == "" {
		reason = defaultEventReason(eventType)
	}

	r.mu.Lock()
	workloadName := r.workloadName
	workloadNamespace := r.workloadNamespace
	effectiveVersion := r.effectiveVersion
	source, sourceOK := r.sourcePolicyByRule[fields["rule"]]
	r.mu.Unlock()

	observedAt := event.At
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	report := eventReportEvent{
		ID:                     fmt.Sprintf("%s:%d", r.proxyID, event.ID),
		ObservedAt:             observedAt,
		Type:                   eventType,
		Severity:               severity,
		Message:                event.Message,
		Count:                  1,
		FirstObservedAt:        observedAt,
		LastObservedAt:         observedAt,
		ProxyID:                r.proxyID,
		ProxyType:              r.proxyType,
		WorkloadIdentity:       r.workloadIdentity,
		WorkloadName:           workloadName,
		WorkloadNamespace:      workloadNamespace,
		EffectivePolicyVersion: effectiveVersion,
		Destination:            eventDestination(fields),
		Reason:                 reason,
		Attributes:             safeEventAttributes(fields),
	}
	if sourceOK {
		report.SourcePolicyName = source.Name
		report.SourcePolicyNamespace = source.Namespace
	}
	return report, true
}

func copyDecisionFields(fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(fields))
	for key, value := range fields {
		out[key] = value
	}
	return out
}

func (r *EventReporter) suppressionEvent(now time.Time, count uint64) eventReportEvent {
	return eventReportEvent{
		ID:                     fmt.Sprintf("%s:suppressed:%d", r.proxyID, now.UnixNano()),
		ObservedAt:             now,
		Type:                   "event.suppressed",
		Severity:               "warning",
		Message:                "proxy event reporter suppressed events before reporting",
		Count:                  count,
		FirstObservedAt:        now,
		LastObservedAt:         now,
		ProxyID:                r.proxyID,
		ProxyType:              r.proxyType,
		WorkloadIdentity:       r.workloadIdentity,
		WorkloadName:           r.workloadName,
		WorkloadNamespace:      r.workloadNamespace,
		EffectivePolicyVersion: r.effectiveVersion,
		Reason:                 "proxy_pending_limit",
	}
}

func (r *EventReporter) export(ctx context.Context, events []eventReportEvent) error {
	body, err := json.Marshal(eventReportPayload{Events: events})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "airlock-proxy-worker/0.1")
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("event endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func defaultEventReason(eventType string) string {
	switch eventType {
	case "egress.denied":
		return "policy_denied"
	case "secret.resolve_failed":
		return "secret_dependency_failed"
	default:
		return "proxy_error"
	}
}

func eventAggregationKey(event eventReportEvent) string {
	destination := ""
	if event.Destination != nil {
		destination = fmt.Sprintf("%s://%s:%d", event.Destination.Scheme, event.Destination.Host, event.Destination.Port)
	}
	return strings.Join([]string{
		event.Type,
		event.Reason,
		destination,
		event.SourcePolicyNamespace,
		event.SourcePolicyName,
		event.Message,
	}, "|")
}

func eventDestination(fields map[string]string) *eventReportDestination {
	raw := strings.TrimSpace(fields["destination"])
	if raw == "" {
		return nil
	}
	host, portString, err := net.SplitHostPort(raw)
	if err != nil {
		return &eventReportDestination{Host: raw}
	}
	port, _ := strconv.ParseUint(portString, 10, 32)
	scheme := "http"
	if strings.EqualFold(fields["method"], "CONNECT") || port == 443 {
		scheme = "https"
	}
	return &eventReportDestination{
		Scheme: scheme,
		Host:   host,
		Port:   uint32(port),
	}
}

func safeEventAttributes(fields map[string]string) map[string]string {
	out := map[string]string{}
	for _, key := range []string{"method", "rule", "dependency"} {
		if value := strings.TrimSpace(fields[key]); value != "" {
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

type eventReportPayload struct {
	Events []eventReportEvent `json:"events"`
}

type eventReportEvent struct {
	ID                     string                  `json:"id"`
	ObservedAt             time.Time               `json:"observedAt"`
	Type                   string                  `json:"type"`
	Severity               string                  `json:"severity"`
	Message                string                  `json:"message"`
	Count                  uint64                  `json:"count"`
	FirstObservedAt        time.Time               `json:"firstObservedAt"`
	LastObservedAt         time.Time               `json:"lastObservedAt"`
	ProxyID                string                  `json:"proxyId"`
	ProxyType              string                  `json:"proxyType,omitempty"`
	WorkloadIdentity       string                  `json:"workloadIdentity"`
	WorkloadName           string                  `json:"workloadName,omitempty"`
	WorkloadNamespace      string                  `json:"workloadNamespace,omitempty"`
	EffectivePolicyVersion string                  `json:"effectivePolicyVersion,omitempty"`
	SourcePolicyName       string                  `json:"sourcePolicyName,omitempty"`
	SourcePolicyNamespace  string                  `json:"sourcePolicyNamespace,omitempty"`
	Destination            *eventReportDestination `json:"destination,omitempty"`
	Reason                 string                  `json:"reason,omitempty"`
	Attributes             map[string]string       `json:"attributes,omitempty"`
}

type eventReportDestination struct {
	Scheme string `json:"scheme,omitempty"`
	Host   string `json:"host"`
	Port   uint32 `json:"port,omitempty"`
}
