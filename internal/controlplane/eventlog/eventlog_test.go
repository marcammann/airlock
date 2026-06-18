package eventlog

import (
	"testing"
	"time"
)

func TestNormalizeDefaultsValidEvent(t *testing.T) {
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	event, ok := Normalize(AdminEvent{
		Type:             " egress.denied ",
		ProxyID:          " 10.42.0.17 ",
		WorkloadIdentity: " spiffe://airlock.local/ns/demo/sa/app ",
	}, now)
	if !ok {
		t.Fatal("Normalize() ok = false, want true")
	}
	if event.Type != "egress.denied" || event.Severity != "warning" {
		t.Fatalf("event type/severity = %q/%q, want egress.denied/warning", event.Type, event.Severity)
	}
	if event.ProxyID != "10.42.0.17" || event.WorkloadIdentity != "spiffe://airlock.local/ns/demo/sa/app" {
		t.Fatalf("event identities not trimmed: %+v", event)
	}
	if event.Count != 1 || event.ObservedAt != now || event.FirstObservedAt == nil || event.LastObservedAt == nil {
		t.Fatalf("event defaults = %+v, want count/time defaults", event)
	}
	if event.ID == "" || event.Message != "egress.denied" {
		t.Fatalf("event id/message = %q/%q, want generated id and type message", event.ID, event.Message)
	}
}

func TestNormalizeRejectsInvalidEvent(t *testing.T) {
	if _, ok := Normalize(AdminEvent{Type: "egress.allowed", ProxyID: "proxy", WorkloadIdentity: "workload"}, time.Now()); ok {
		t.Fatal("Normalize() ok = true for unsupported type")
	}
	if _, ok := Normalize(AdminEvent{Type: "egress.denied", WorkloadIdentity: "workload"}, time.Now()); ok {
		t.Fatal("Normalize() ok = true without proxy id")
	}
}

func TestCursorRoundTripAndOrdering(t *testing.T) {
	newer := AdminEvent{ID: "newer", ObservedAt: time.Date(2026, 6, 18, 12, 0, 1, 0, time.UTC)}
	cursor, err := ParseCursor(CursorFor(newer))
	if err != nil {
		t.Fatal(err)
	}
	older := AdminEvent{ID: "older", ObservedAt: newer.ObservedAt.Add(-time.Second)}
	if !BeforeCursor(older, *cursor) {
		t.Fatal("older event should be before cursor")
	}
	if BeforeCursor(AdminEvent{ID: "later", ObservedAt: newer.ObservedAt.Add(time.Second)}, *cursor) {
		t.Fatal("newer event should not be before cursor")
	}
	if !After(newer, older) {
		t.Fatal("newer event should sort after older")
	}
}

func TestBucketAllowRateLimits(t *testing.T) {
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	bucket, ok := BucketAllow(IngestBucket{}, 1, 1, now)
	if !ok {
		t.Fatal("first BucketAllow() ok = false, want true")
	}
	if _, ok := BucketAllow(bucket, 1, 1, now); ok {
		t.Fatal("second BucketAllow() ok = true, want rate limited")
	}
	refilled, ok := BucketAllow(bucket, 1, 1, now.Add(time.Second))
	if !ok {
		t.Fatal("refilled BucketAllow() ok = false, want true")
	}
	if refilled.Tokens != 0 {
		t.Fatalf("tokens = %v, want 0 after consuming refill", refilled.Tokens)
	}
}

func TestSuppressionsSortsAndDropsZeroCounts(t *testing.T) {
	got := Suppressions(map[string]uint64{"b": 2, "a": 0, "c": 1})
	if len(got) != 2 || got[0].ProxyID != "b" || got[0].Count != 2 || got[1].ProxyID != "c" || got[1].Count != 1 {
		t.Fatalf("Suppressions() = %+v, want non-zero sorted counts", got)
	}
}
