package ratelimit

import (
	"net/http"
	"testing"
	"time"
)

func TestAllowConsumesBurstAndComputesRetryAfter(t *testing.T) {
	now := time.Now().UTC()
	limit := Limit{RatePerSecond: 1, Burst: 1}

	bucket, allowed, retryAfter := Allow(Bucket{}, limit, now)
	if !allowed || retryAfter != 0 {
		t.Fatalf("first allowed=%t retryAfter=%s, want allowed", allowed, retryAfter)
	}

	bucket, allowed, retryAfter = Allow(bucket, limit, now)
	if allowed || retryAfter != time.Second {
		t.Fatalf("second allowed=%t retryAfter=%s, want one second retry", allowed, retryAfter)
	}

	_, allowed, retryAfter = Allow(bucket, limit, now.Add(time.Second))
	if !allowed || retryAfter != 0 {
		t.Fatalf("after refill allowed=%t retryAfter=%s, want allowed", allowed, retryAfter)
	}
}

func TestKeyUsesIdentityBeforeRemoteIP(t *testing.T) {
	request := &http.Request{RemoteAddr: "192.0.2.10:1234"}
	if got := Key("alice", request); got != "identity:alice" {
		t.Fatalf("key = %q, want identity key", got)
	}
	if got := Key("", request); got != "ip:192.0.2.10" {
		t.Fatalf("key = %q, want remote ip key", got)
	}
}
