package controlplane

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type EventLogMode string

const (
	EventLogDisabled EventLogMode = "disabled"
	EventLogMemory   EventLogMode = "memory"
)

type AdminEventsResponse struct {
	Events     []AdminEvent       `json:"events"`
	NextCursor string             `json:"nextCursor,omitempty"`
	Source     string             `json:"source"`
	Suppressed []EventSuppression `json:"suppressed,omitempty"`
}

type EventSuppression struct {
	ProxyID string `json:"proxyId"`
	Count   uint64 `json:"count"`
}

type IngestEventsResponse struct {
	OK         bool   `json:"ok"`
	Accepted   int    `json:"accepted"`
	Stored     int    `json:"stored"`
	Suppressed uint64 `json:"suppressed"`
}

type AdminEvent struct {
	ID                     string            `json:"id"`
	ObservedAt             time.Time         `json:"observedAt"`
	Type                   string            `json:"type"`
	Severity               string            `json:"severity"`
	Message                string            `json:"message"`
	Count                  uint64            `json:"count"`
	FirstObservedAt        *time.Time        `json:"firstObservedAt,omitempty"`
	LastObservedAt         *time.Time        `json:"lastObservedAt,omitempty"`
	ProxyID                string            `json:"proxyId"`
	ProxyType              string            `json:"proxyType,omitempty"`
	WorkloadIdentity       string            `json:"workloadIdentity"`
	WorkloadName           string            `json:"workloadName,omitempty"`
	WorkloadNamespace      string            `json:"workloadNamespace,omitempty"`
	EffectivePolicyVersion string            `json:"effectivePolicyVersion,omitempty"`
	SourcePolicyName       string            `json:"sourcePolicyName,omitempty"`
	SourcePolicyNamespace  string            `json:"sourcePolicyNamespace,omitempty"`
	Destination            *EventDestination `json:"destination,omitempty"`
	Reason                 string            `json:"reason,omitempty"`
	Attributes             map[string]string `json:"attributes,omitempty"`
}

type EventDestination struct {
	Scheme string `json:"scheme,omitempty"`
	Host   string `json:"host"`
	Port   uint32 `json:"port,omitempty"`
}

type ingestEventsRequest struct {
	Events []AdminEvent `json:"events"`
}

type eventIngestBucket struct {
	Tokens float64
	Last   time.Time
}

func (s *Server) handleIngestEvents(w http.ResponseWriter, r *http.Request) {
	var payload ingestEventsRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
		s.recordAudit(r, "ingest_events", "bad_request", "", "", nil)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid events payload"})
		return
	}
	if len(payload.Events) == 0 {
		writeJSON(w, http.StatusOK, IngestEventsResponse{OK: true})
		return
	}
	if len(payload.Events) > 100 {
		payload.Events = payload.Events[:100]
	}

	workloadIdentity := strings.TrimSpace(payload.Events[0].WorkloadIdentity)
	if workloadIdentity == "" {
		s.recordAudit(r, "ingest_events", "bad_request", "", "", nil)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "events require workloadIdentity"})
		return
	}
	for _, event := range payload.Events {
		if strings.TrimSpace(event.WorkloadIdentity) != workloadIdentity {
			s.recordAudit(r, "ingest_events", "bad_request", strings.TrimSpace(event.WorkloadIdentity), "", nil)
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "all events must include the same workloadIdentity"})
			return
		}
	}

	authenticatedIdentity, ok := s.authorized(r, workloadIdentity)
	if !ok {
		s.recordAudit(r, "ingest_events", "unauthorized", workloadIdentity, authenticatedIdentity, nil)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	now := time.Now().UTC()
	accepted := 0
	stored := 0
	var suppressed uint64
	if s.eventLogMode == EventLogDisabled {
		s.recordAudit(r, "ingest_events", "allowed", workloadIdentity, authenticatedIdentity, nil)
		writeJSON(w, http.StatusOK, IngestEventsResponse{OK: true, Accepted: len(payload.Events)})
		return
	}

	s.mu.Lock()
	s.pruneEventsLocked(now)
	for _, event := range payload.Events {
		normalized, valid := normalizeAdminEvent(event, now)
		if !valid {
			continue
		}
		accepted++
		if !s.allowEventIngestLocked(normalized.ProxyID, now) {
			suppressed += normalized.Count
			s.eventSuppressed[normalized.ProxyID] += normalized.Count
			continue
		}
		s.events = append(s.events, normalized)
		stored++
	}
	s.trimEventsLocked()
	s.mu.Unlock()

	s.recordAudit(r, "ingest_events", "allowed", workloadIdentity, authenticatedIdentity, nil)
	writeJSON(w, http.StatusOK, IngestEventsResponse{
		OK:         true,
		Accepted:   accepted,
		Stored:     stored,
		Suppressed: suppressed,
	})
}

func (s *Server) handleListAdminEvents(w http.ResponseWriter, r *http.Request) {
	auth := s.authorizedAdmin(r, AdminPermissionAuditRead)
	if !auth.ok {
		s.recordAudit(r, "list_admin_events", auth.outcome(), "", auth.identity, nil)
		writeJSON(w, auth.status(), map[string]any{"error": auth.outcome()})
		return
	}

	proxyID := strings.TrimSpace(r.URL.Query().Get("proxy_id"))
	eventType := strings.TrimSpace(r.URL.Query().Get("type"))
	severity := strings.TrimSpace(r.URL.Query().Get("severity"))
	limit := parseEventLimit(r.URL.Query().Get("limit"))
	cursor, err := parseEventCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		s.recordAudit(r, "list_admin_events", "bad_request", "", auth.identity, nil)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid cursor"})
		return
	}

	now := time.Now().UTC()
	s.mu.Lock()
	s.pruneEventsLocked(now)
	events := make([]AdminEvent, 0, len(s.events))
	for _, event := range s.events {
		if proxyID != "" && event.ProxyID != proxyID {
			continue
		}
		if eventType != "" && event.Type != eventType {
			continue
		}
		if severity != "" && event.Severity != severity {
			continue
		}
		if cursor != nil && !eventBeforeCursor(event, *cursor) {
			continue
		}
		events = append(events, event)
	}
	suppressed := eventSuppressions(s.eventSuppressed)
	s.mu.Unlock()

	sort.Slice(events, func(i, j int) bool {
		return eventAfter(events[i], events[j])
	})
	nextCursor := ""
	if len(events) > limit {
		nextCursor = eventCursorFor(events[limit-1])
		events = events[:limit]
	}

	s.recordAudit(r, "list_admin_events", "allowed", "", auth.identity, nil)
	writeJSON(w, http.StatusOK, AdminEventsResponse{
		Events:     events,
		NextCursor: nextCursor,
		Source:     eventLogSource(s.eventLogMode),
		Suppressed: suppressed,
	})
}

func normalizeAdminEvent(event AdminEvent, now time.Time) (AdminEvent, bool) {
	event.Type = strings.TrimSpace(event.Type)
	event.Severity = strings.TrimSpace(event.Severity)
	event.ProxyID = strings.TrimSpace(event.ProxyID)
	event.WorkloadIdentity = strings.TrimSpace(event.WorkloadIdentity)
	event.ID = strings.TrimSpace(event.ID)
	event.Message = strings.TrimSpace(event.Message)
	event.Reason = strings.TrimSpace(event.Reason)
	if !allowedEventType(event.Type) || event.ProxyID == "" || event.WorkloadIdentity == "" {
		return AdminEvent{}, false
	}
	if event.Severity == "" {
		event.Severity = severityForEventType(event.Type)
	}
	if event.Count == 0 {
		event.Count = 1
	}
	if event.ObservedAt.IsZero() {
		event.ObservedAt = now
	}
	if event.FirstObservedAt == nil {
		first := event.ObservedAt
		event.FirstObservedAt = &first
	}
	if event.LastObservedAt == nil {
		last := event.ObservedAt
		event.LastObservedAt = &last
	}
	if event.ID == "" {
		event.ID = fmt.Sprintf("%s:%s:%d", event.ProxyID, event.Type, event.ObservedAt.UnixNano())
	}
	if event.Message == "" {
		event.Message = event.Type
	}
	return event, true
}

func allowedEventType(eventType string) bool {
	switch eventType {
	case "egress.denied", "proxy.error", "policy.fetch_failed", "secret.resolve_failed", "control_plane.auth_failed", "event.suppressed":
		return true
	default:
		return false
	}
}

func severityForEventType(eventType string) string {
	switch eventType {
	case "egress.denied", "event.suppressed":
		return "warning"
	default:
		return "error"
	}
}

func eventLogSource(mode EventLogMode) string {
	if mode == EventLogDisabled {
		return "event-log-disabled"
	}
	return "event-log-memory"
}

func (s *Server) pruneEventsLocked(now time.Time) {
	if s.eventLogTTL <= 0 || len(s.events) == 0 {
		return
	}
	cutoff := now.Add(-s.eventLogTTL)
	start := 0
	for start < len(s.events) && s.events[start].ObservedAt.Before(cutoff) {
		start++
	}
	if start > 0 {
		s.events = append([]AdminEvent(nil), s.events[start:]...)
	}
}

func (s *Server) trimEventsLocked() {
	if s.eventLogLimit <= 0 || len(s.events) <= s.eventLogLimit {
		return
	}
	s.events = append([]AdminEvent(nil), s.events[len(s.events)-s.eventLogLimit:]...)
}

func (s *Server) allowEventIngestLocked(proxyID string, now time.Time) bool {
	if proxyID == "" {
		proxyID = "unknown"
	}
	proxyBucket, ok := eventBucketAllow(
		s.eventIngestBuckets[proxyID],
		s.eventIngestRatePerProxy,
		s.eventIngestBurstPerProxy,
		now,
	)
	if !ok {
		s.eventIngestBuckets[proxyID] = proxyBucket
		return false
	}
	globalBucket, ok := eventBucketAllow(
		s.eventIngestGlobalBucket,
		s.eventIngestRate,
		s.eventIngestBurst,
		now,
	)
	if !ok {
		s.eventIngestGlobalBucket = globalBucket
		return false
	}
	s.eventIngestBuckets[proxyID] = proxyBucket
	s.eventIngestGlobalBucket = globalBucket
	return true
}

func eventBucketAllow(bucket eventIngestBucket, rate float64, burst int, now time.Time) (eventIngestBucket, bool) {
	if rate <= 0 || burst <= 0 {
		return bucket, true
	}
	if bucket.Last.IsZero() {
		bucket.Tokens = float64(burst)
	} else {
		elapsed := now.Sub(bucket.Last).Seconds()
		bucket.Tokens += elapsed * rate
		if maxTokens := float64(burst); bucket.Tokens > maxTokens {
			bucket.Tokens = maxTokens
		}
	}
	bucket.Last = now
	if bucket.Tokens < 1 {
		return bucket, false
	}
	bucket.Tokens--
	return bucket, true
}

func eventSuppressions(counts map[string]uint64) []EventSuppression {
	out := make([]EventSuppression, 0, len(counts))
	for proxyID, count := range counts {
		if count == 0 {
			continue
		}
		out = append(out, EventSuppression{ProxyID: proxyID, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ProxyID < out[j].ProxyID
	})
	return out
}

type eventCursor struct {
	ObservedAt string `json:"observedAt"`
	ID         string `json:"id"`
}

func parseEventLimit(raw string) int {
	if raw == "" {
		return 50
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return 50
	}
	if value > 100 {
		return 100
	}
	return value
}

func parseEventCursor(raw string) (*eventCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var cursor eventCursor
	if err := json.Unmarshal(data, &cursor); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cursor.ObservedAt) == "" || strings.TrimSpace(cursor.ID) == "" {
		return nil, fmt.Errorf("cursor is missing observedAt or id")
	}
	return &cursor, nil
}

func eventCursorFor(event AdminEvent) string {
	data, err := json.Marshal(eventCursor{
		ObservedAt: event.ObservedAt.Format(time.RFC3339Nano),
		ID:         event.ID,
	})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func eventBeforeCursor(event AdminEvent, cursor eventCursor) bool {
	cursorAt, err := time.Parse(time.RFC3339Nano, cursor.ObservedAt)
	if err != nil {
		return false
	}
	if event.ObservedAt.Before(cursorAt) {
		return true
	}
	if event.ObservedAt.Equal(cursorAt) {
		return event.ID < cursor.ID
	}
	return false
}

func eventAfter(left AdminEvent, right AdminEvent) bool {
	if !left.ObservedAt.Equal(right.ObservedAt) {
		return left.ObservedAt.After(right.ObservedAt)
	}
	return left.ID > right.ID
}
