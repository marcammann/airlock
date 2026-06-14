package proxyworker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type EventReporter struct {
	endpoint           string
	devToken           string
	client             *http.Client
	proxyID            string
	proxyType          string
	workloadIdentity   string
	workloadName       string
	workloadNamespace  string
	effectiveVersion   string
	sourcePolicyByRule map[string]PolicyRef
	flushInterval      time.Duration
	maxPendingKeys     int

	mu         sync.Mutex
	pending    map[string]*pendingAirlockEvent
	suppressed uint64
	bucket     reportTokenBucket
}

type EventReporterOptions struct {
	Endpoint           string
	DevToken           string
	ProxyID            string
	ProxyType          string
	WorkloadIdentity   string
	WorkloadName       string
	WorkloadNamespace  string
	EffectiveVersion   string
	SourcePolicyByRule map[string]PolicyRef
	Client             *http.Client
	RatePerSecond      float64
	Burst              int
	FlushInterval      time.Duration
	MaxPendingKeys     int
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
		devToken:           opts.DevToken,
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

func (r *EventReporter) Run(ctx context.Context) {
	fmt.Fprintf(os.Stderr, "airlock-proxy-worker event reporting enabled proxy_id=%s endpoint=%s rate=%.2f/s burst=%d\n", r.proxyID, r.endpoint, r.bucket.Rate, r.bucket.Burst)
	ticker := time.NewTicker(r.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = r.Flush(context.Background())
			return
		case <-ticker.C:
			if err := r.Flush(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "airlock-proxy-worker event report failed proxy_id=%s error=%q\n", r.proxyID, err.Error())
			}
		}
	}
}

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
	if event.Decision == "allowed" {
		return eventReportEvent{}, false
	}
	fields := keyValueFields(event.Message)
	eventType := "egress.denied"
	severity := "warning"
	reason := fields["reason"]
	if event.Decision == "proxy_error" {
		eventType = "proxy.error"
		severity = "error"
		if fields["dependency"] == "secret" {
			eventType = "secret.resolve_failed"
			reason = "secret_dependency_failed"
		}
	}
	if reason == "" {
		reason = defaultEventReason(eventType)
	}

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
		WorkloadName:           r.workloadName,
		WorkloadNamespace:      r.workloadNamespace,
		EffectivePolicyVersion: r.effectiveVersion,
		Destination:            eventDestination(fields),
		Reason:                 reason,
		Attributes:             safeEventAttributes(fields),
	}
	if rule := fields["rule"]; rule != "" {
		if source, ok := r.sourcePolicyByRule[rule]; ok {
			report.SourcePolicyName = source.Name
			report.SourcePolicyNamespace = source.Namespace
		}
	}
	return report, true
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
	if r.devToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.devToken)
	}
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

func keyValueFields(message string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Fields(message) {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out[key] = strings.Trim(value, `"'`)
	}
	return out
}
