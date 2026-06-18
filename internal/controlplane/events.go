package controlplane

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/marcammann/airlock/internal/controlplane/eventlog"
	"github.com/marcammann/airlock/internal/telemetry"
)

// EventLogMode selects the control-plane event log backend.
type EventLogMode = eventlog.Mode

const (
	// EventLogDisabled disables local event retention.
	EventLogDisabled EventLogMode = eventlog.ModeDisabled
	// EventLogMemory retains recent events in memory.
	EventLogMemory EventLogMode = eventlog.ModeMemory
)

// AdminEventsResponse is returned by the admin event listing endpoint.
type AdminEventsResponse = eventlog.AdminEventsResponse

// EventSuppression reports suppressed event counts.
type EventSuppression = eventlog.Suppression

// IngestEventsResponse is returned by the worker event ingestion endpoint.
type IngestEventsResponse = eventlog.IngestEventsResponse

// AdminEvent is one event visible to administrators.
type AdminEvent = eventlog.AdminEvent

// EventDestination describes the egress destination associated with an event.
type EventDestination = eventlog.Destination

type ingestEventsRequest struct {
	Events []AdminEvent `json:"events"`
}

type eventIngestBucket = eventlog.IngestBucket

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
		telemetry.ObserveControlPlaneEventsIngested(len(payload.Events))
		writeJSON(w, http.StatusOK, IngestEventsResponse{OK: true, Accepted: len(payload.Events)})
		return
	}

	invalid := 0
	s.mu.Lock()
	s.pruneEventsLocked(now)
	for _, event := range payload.Events {
		normalized, valid := eventlog.Normalize(event, now)
		if !valid {
			invalid++
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

	telemetry.ObserveControlPlaneEventsIngested(stored)
	telemetry.ObserveControlPlaneEventsDropped("invalid", uint64(invalid))
	telemetry.ObserveControlPlaneEventsDropped("rate_limited", suppressed)
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
	if !s.allowAdminRead(w, r, auth, "list_admin_events") {
		return
	}

	proxyID := strings.TrimSpace(r.URL.Query().Get("proxy_id"))
	eventType := strings.TrimSpace(r.URL.Query().Get("type"))
	severity := strings.TrimSpace(r.URL.Query().Get("severity"))
	limit := eventlog.ParseLimit(r.URL.Query().Get("limit"))
	cursor, err := eventlog.ParseCursor(r.URL.Query().Get("cursor"))
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
		if cursor != nil && !eventlog.BeforeCursor(event, *cursor) {
			continue
		}
		events = append(events, event)
	}
	suppressed := eventlog.Suppressions(s.eventSuppressed)
	s.mu.Unlock()

	sort.Slice(events, func(i, j int) bool {
		return eventlog.After(events[i], events[j])
	})
	nextCursor := ""
	if len(events) > limit {
		nextCursor = eventlog.CursorFor(events[limit-1])
		events = events[:limit]
	}

	s.recordAudit(r, "list_admin_events", "allowed", "", auth.identity, nil)
	writeJSON(w, http.StatusOK, AdminEventsResponse{
		Events:     events,
		NextCursor: nextCursor,
		Source:     eventlog.Source(s.eventLogMode),
		Suppressed: suppressed,
	})
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
	proxyBucket, ok := eventlog.BucketAllow(
		s.eventIngestBuckets[proxyID],
		s.eventIngestRatePerProxy,
		s.eventIngestBurstPerProxy,
		now,
	)
	if !ok {
		s.eventIngestBuckets[proxyID] = proxyBucket
		return false
	}
	globalBucket, ok := eventlog.BucketAllow(
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
