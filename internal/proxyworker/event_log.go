package proxyworker

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

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

type DecisionEvent struct {
	ID       uint64
	At       time.Time
	Decision string
	Message  string
}

type DecisionSink interface {
	RecordDecision(DecisionEvent)
}

type EventLogSnapshot struct {
	Allowed        uint64
	Denied         uint64
	ProxyError     uint64
	LastDecisionAt *time.Time
	DecisionEvents []DecisionEvent
}

func NewEventLog(writer io.Writer) *EventLog {
	if writer == nil {
		writer = io.Discard
	}
	return &EventLog{writer: writer}
}

func NewStderrEventLog() *EventLog {
	return NewEventLog(os.Stderr)
}

func NewMemoryEventLog() *EventLog {
	return &EventLog{writer: io.Discard}
}

func (l *EventLog) Record(message string) {
	var event *DecisionEvent
	var sink DecisionSink
	l.mu.Lock()
	l.entries = append(l.entries, message)
	event = l.observeDecisionLocked(message)
	sink = l.decisionSink
	l.mu.Unlock()
	_, _ = fmt.Fprintln(l.writer, message)
	if event != nil && sink != nil {
		sink.RecordDecision(*event)
	}
}

func (l *EventLog) SetDecisionSink(sink DecisionSink) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.decisionSink = sink
}

func (l *EventLog) Entries() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.entries))
	copy(out, l.entries)
	return out
}

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

func (l *EventLog) observeDecisionLocked(message string) *DecisionEvent {
	now := time.Now().UTC()
	switch {
	case containsAll(message, "allowed", "request"), containsAll(message, "allowed", "CONNECT"):
		l.allowed++
		l.lastDecisionAt = &now
		return l.appendDecisionEventLocked(now, "allowed", message)
	case containsAll(message, "denied", "dependency=secret"):
		l.proxyError++
		l.lastDecisionAt = &now
		return l.appendDecisionEventLocked(now, "proxy_error", message)
	case containsAll(message, "denied", "request"), containsAll(message, "denied", "CONNECT"):
		l.denied++
		l.lastDecisionAt = &now
		return l.appendDecisionEventLocked(now, "denied", message)
	}
	return nil
}

func (l *EventLog) appendDecisionEventLocked(at time.Time, decision string, message string) *DecisionEvent {
	l.nextEventID++
	event := DecisionEvent{
		ID:       l.nextEventID,
		At:       at,
		Decision: decision,
		Message:  message,
	}
	l.decisionEvents = append(l.decisionEvents, event)
	const maxDecisionEvents = 100
	if len(l.decisionEvents) > maxDecisionEvents {
		l.decisionEvents = l.decisionEvents[len(l.decisionEvents)-maxDecisionEvents:]
	}
	return &event
}

func containsAll(value string, needles ...string) bool {
	for _, needle := range needles {
		if !contains(value, needle) {
			return false
		}
	}
	return true
}

func contains(value string, needle string) bool {
	return strings.Contains(value, needle)
}
