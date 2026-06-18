// Package telemetry contains proxy-worker runtime logs and decision telemetry.
package telemetry

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	airlockmetrics "github.com/marcammann/airlock/internal/telemetry"
)

// EventLog records local proxy decisions and forwards decision events to a sink.
type EventLog struct {
	mu             sync.Mutex
	writer         io.Writer
	entries        []string
	decisionSink   DecisionSink
	decisionEvents []DecisionEvent
	nextEventID    uint64
	allowed        uint64
	denied         uint64
	proxyError     uint64
	lastDecisionAt *time.Time
}

// DecisionKind classifies a proxy decision for counters and event reporting.
type DecisionKind string

const (
	// DecisionNone records a message without updating decision counters.
	DecisionNone DecisionKind = ""
	// DecisionAllow records an allowed egress decision.
	DecisionAllow DecisionKind = "allowed"
	// DecisionDeny records a policy-denied egress decision.
	DecisionDeny DecisionKind = "denied"
	// DecisionProxyError records a proxy or upstream dependency failure.
	DecisionProxyError DecisionKind = "proxy_error"
	// DecisionSecretError records a secret resolution failure.
	DecisionSecretError DecisionKind = "secret_error"
)

// DecisionEvent is one structured proxy decision emitted by EventLog.
type DecisionEvent struct {
	ID       uint64
	At       time.Time
	Decision DecisionKind
	Message  string
	Fields   map[string]string
}

// DecisionSink receives structured decision events as they are recorded.
type DecisionSink interface {
	RecordDecision(DecisionEvent)
}

// EventLogSnapshot is a point-in-time copy of decision counters and events.
type EventLogSnapshot struct {
	Allowed        uint64
	Denied         uint64
	ProxyError     uint64
	LastDecisionAt *time.Time
	DecisionEvents []DecisionEvent
}

// NewEventLog creates an event log that writes messages to writer.
func NewEventLog(writer io.Writer) *EventLog {
	if writer == nil {
		writer = io.Discard
	}
	return &EventLog{writer: writer}
}

// NewStderrEventLog creates an event log that writes messages to stderr.
func NewStderrEventLog() *EventLog {
	return NewEventLog(os.Stderr)
}

// NewMemoryEventLog creates an event log that only keeps in-memory state.
func NewMemoryEventLog() *EventLog {
	return &EventLog{writer: io.Discard}
}

// Record writes a message and updates counters for a proxy decision.
func (l *EventLog) Record(kind DecisionKind, message string, fields ...map[string]string) {
	var event *DecisionEvent
	var sink DecisionSink
	l.mu.Lock()
	l.entries = append(l.entries, message)
	event = l.observeDecisionLocked(kind, message, mergeDecisionFields(fields...))
	sink = l.decisionSink
	l.mu.Unlock()
	_, _ = fmt.Fprintln(l.writer, message)
	if event != nil && sink != nil {
		sink.RecordDecision(*event)
	}
}

// SetDecisionSink changes the receiver for future structured decision events.
func (l *EventLog) SetDecisionSink(sink DecisionSink) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.decisionSink = sink
}

// Entries returns a copy of recorded log messages.
func (l *EventLog) Entries() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.entries))
	copy(out, l.entries)
	return out
}

// Snapshot returns a copy of decision counters and retained events.
func (l *EventLog) Snapshot() EventLogSnapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	var lastDecisionAt *time.Time
	if l.lastDecisionAt != nil {
		value := *l.lastDecisionAt
		lastDecisionAt = &value
	}
	events := make([]DecisionEvent, len(l.decisionEvents))
	copy(events, l.decisionEvents)
	return EventLogSnapshot{
		Allowed:        l.allowed,
		Denied:         l.denied,
		ProxyError:     l.proxyError,
		LastDecisionAt: lastDecisionAt,
		DecisionEvents: events,
	}
}

func (l *EventLog) observeDecisionLocked(kind DecisionKind, message string, fields map[string]string) *DecisionEvent {
	if kind == DecisionNone {
		return nil
	}
	now := time.Now().UTC()
	switch kind {
	case DecisionAllow:
		l.allowed++
		l.lastDecisionAt = &now
		airlockmetrics.ObserveProxyDecision(string(kind))
		return l.appendDecisionEventLocked(now, kind, message, fields)
	case DecisionSecretError, DecisionProxyError:
		l.proxyError++
		l.lastDecisionAt = &now
		airlockmetrics.ObserveProxyDecision(string(kind))
		return l.appendDecisionEventLocked(now, kind, message, fields)
	case DecisionDeny:
		l.denied++
		l.lastDecisionAt = &now
		airlockmetrics.ObserveProxyDecision(string(kind))
		return l.appendDecisionEventLocked(now, kind, message, fields)
	}
	return nil
}

func (l *EventLog) appendDecisionEventLocked(at time.Time, decision DecisionKind, message string, fields map[string]string) *DecisionEvent {
	l.nextEventID++
	event := DecisionEvent{
		ID:       l.nextEventID,
		At:       at,
		Decision: decision,
		Message:  message,
		Fields:   fields,
	}
	l.decisionEvents = append(l.decisionEvents, event)
	const maxDecisionEvents = 100
	if len(l.decisionEvents) > maxDecisionEvents {
		l.decisionEvents = l.decisionEvents[len(l.decisionEvents)-maxDecisionEvents:]
	}
	return &event
}

func mergeDecisionFields(fields ...map[string]string) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, fieldSet := range fields {
		for key, value := range fieldSet {
			if key == "" || value == "" {
				continue
			}
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
