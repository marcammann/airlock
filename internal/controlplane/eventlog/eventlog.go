// Package eventlog contains Airlock control-plane event models and helpers.
package eventlog

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Mode selects the control-plane event log backend.
type Mode string

const (
	// ModeDisabled disables local event retention.
	ModeDisabled Mode = "disabled"
	// ModeMemory retains recent events in control-plane memory.
	ModeMemory Mode = "memory"
)

// AdminEventsResponse is returned by the admin event listing endpoint.
type AdminEventsResponse struct {
	Events     []AdminEvent  `json:"events"`
	NextCursor string        `json:"nextCursor,omitempty"`
	Source     string        `json:"source"`
	Suppressed []Suppression `json:"suppressed,omitempty"`
}

// Suppression reports how many events were dropped for a proxy.
type Suppression struct {
	ProxyID string `json:"proxyId"`
	Count   uint64 `json:"count"`
}

// IngestEventsResponse is returned by the worker event ingestion endpoint.
type IngestEventsResponse struct {
	OK         bool   `json:"ok"`
	Accepted   int    `json:"accepted"`
	Stored     int    `json:"stored"`
	Suppressed uint64 `json:"suppressed"`
}

// AdminEvent is one event visible to Airlock administrators.
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
	Destination            *Destination      `json:"destination,omitempty"`
	Reason                 string            `json:"reason,omitempty"`
	Attributes             map[string]string `json:"attributes,omitempty"`
}

// Destination describes the egress destination associated with an event.
type Destination struct {
	Scheme string `json:"scheme,omitempty"`
	Host   string `json:"host"`
	Port   uint32 `json:"port,omitempty"`
}

// IngestBucket tracks token-bucket state for event ingestion.
type IngestBucket struct {
	Tokens float64
	Last   time.Time
}

// Cursor is an opaque event pagination cursor after decoding.
type Cursor struct {
	ObservedAt string `json:"observedAt"`
	ID         string `json:"id"`
}

// Normalize validates and fills defaults on an admin event.
func Normalize(event AdminEvent, now time.Time) (AdminEvent, bool) {
	event.Type = strings.TrimSpace(event.Type)
	event.Severity = strings.TrimSpace(event.Severity)
	event.ProxyID = strings.TrimSpace(event.ProxyID)
	event.WorkloadIdentity = strings.TrimSpace(event.WorkloadIdentity)
	event.ID = strings.TrimSpace(event.ID)
	event.Message = strings.TrimSpace(event.Message)
	event.Reason = strings.TrimSpace(event.Reason)
	if !AllowedType(event.Type) || event.ProxyID == "" || event.WorkloadIdentity == "" {
		return AdminEvent{}, false
	}
	if event.Severity == "" {
		event.Severity = SeverityForType(event.Type)
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

// AllowedType reports whether the control plane accepts the event type.
func AllowedType(eventType string) bool {
	switch eventType {
	case "egress.denied", "proxy.error", "policy.fetch_failed", "secret.resolve_failed", "control_plane.auth_failed", "event.suppressed":
		return true
	default:
		return false
	}
}

// SeverityForType returns the default severity for an event type.
func SeverityForType(eventType string) string {
	switch eventType {
	case "egress.denied", "event.suppressed":
		return "warning"
	default:
		return "error"
	}
}

// Source returns the admin-visible source name for an event log mode.
func Source(mode Mode) string {
	if mode == ModeDisabled {
		return "event-log-disabled"
	}
	return "event-log-memory"
}

// BucketAllow consumes one token from an event ingestion bucket.
func BucketAllow(bucket IngestBucket, rate float64, burst int, now time.Time) (IngestBucket, bool) {
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

// Suppressions returns sorted non-zero event suppression summaries.
func Suppressions(counts map[string]uint64) []Suppression {
	out := make([]Suppression, 0, len(counts))
	for proxyID, count := range counts {
		if count == 0 {
			continue
		}
		out = append(out, Suppression{ProxyID: proxyID, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ProxyID < out[j].ProxyID
	})
	return out
}

// ParseLimit parses and clamps an admin event page size.
func ParseLimit(raw string) int {
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

// ParseCursor decodes an admin event pagination cursor.
func ParseCursor(raw string) (*Cursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var cursor Cursor
	if err := json.Unmarshal(data, &cursor); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cursor.ObservedAt) == "" || strings.TrimSpace(cursor.ID) == "" {
		return nil, fmt.Errorf("cursor is missing observedAt or id")
	}
	return &cursor, nil
}

// CursorFor returns an encoded pagination cursor for an event.
func CursorFor(event AdminEvent) string {
	data, err := json.Marshal(Cursor{
		ObservedAt: event.ObservedAt.Format(time.RFC3339Nano),
		ID:         event.ID,
	})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

// BeforeCursor reports whether an event should appear after a cursor.
func BeforeCursor(event AdminEvent, cursor Cursor) bool {
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

// After reports whether left sorts newer than right.
func After(left AdminEvent, right AdminEvent) bool {
	if !left.ObservedAt.Equal(right.ObservedAt) {
		return left.ObservedAt.After(right.ObservedAt)
	}
	return left.ID > right.ID
}
