package worker

import (
	"fmt"
	"io"
	"os"
	"sync"
)

type EventLog struct {
	mu      sync.Mutex
	writer  io.Writer
	entries []string
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
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, message)
	_, _ = fmt.Fprintln(l.writer, message)
}

func (l *EventLog) Entries() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.entries))
	copy(out, l.entries)
	return out
}
