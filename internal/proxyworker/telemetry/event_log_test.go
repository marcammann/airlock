package telemetry

import "testing"

func TestEventLogSnapshotCountsDecisions(t *testing.T) {
	log := NewMemoryEventLog()

	log.Record(DecisionAllow, "allowed request", map[string]string{"method": "GET", "destination": "allowed.test:443"})
	log.Record(DecisionDeny, "denied request", map[string]string{"method": "GET", "destination": "denied.test:443", "reason": "no_matching_egress"})
	log.Record(DecisionSecretError, "secret failed", map[string]string{"method": "GET", "destination": "secret.test:443", "dependency": "secret", "reason": "missing"})

	snapshot := log.Snapshot()
	if snapshot.Allowed != 1 || snapshot.Denied != 1 || snapshot.ProxyError != 1 {
		t.Fatalf("snapshot = %+v, want allowed=1 denied=1 proxyError=1", snapshot)
	}
	if snapshot.LastDecisionAt == nil {
		t.Fatal("LastDecisionAt is nil, want decision timestamp")
	}
	if len(snapshot.DecisionEvents) != 3 {
		t.Fatalf("DecisionEvents = %d, want 3", len(snapshot.DecisionEvents))
	}
	if snapshot.DecisionEvents[0].Decision != DecisionAllow ||
		snapshot.DecisionEvents[1].Decision != DecisionDeny ||
		snapshot.DecisionEvents[2].Decision != DecisionSecretError {
		t.Fatalf("DecisionEvents = %+v, want allowed/denied/secret_error", snapshot.DecisionEvents)
	}
}
