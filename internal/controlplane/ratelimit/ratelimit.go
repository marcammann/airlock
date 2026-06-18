// Package ratelimit provides small single-node token bucket helpers.
package ratelimit

import (
	"math"
	"net"
	"net/http"
	"strings"
	"time"
)

// Limit configures a token bucket rate limit.
type Limit struct {
	RatePerSecond float64
	Burst         int
}

// Bucket stores token bucket state for one rate-limit key.
type Bucket struct {
	Tokens float64
	Last   time.Time
}

// BucketTTL is the idle duration after which rate-limit buckets can be pruned.
const BucketTTL = 10 * time.Minute

// Allow consumes one token from a bucket or returns the retry delay.
func Allow(bucket Bucket, limit Limit, now time.Time) (Bucket, bool, time.Duration) {
	if limit.RatePerSecond <= 0 || limit.Burst <= 0 {
		return bucket, true, 0
	}
	if bucket.Last.IsZero() {
		bucket.Tokens = float64(limit.Burst)
	} else {
		bucket.Tokens += now.Sub(bucket.Last).Seconds() * limit.RatePerSecond
		if maxTokens := float64(limit.Burst); bucket.Tokens > maxTokens {
			bucket.Tokens = maxTokens
		}
	}
	bucket.Last = now
	if bucket.Tokens >= 1 {
		bucket.Tokens--
		return bucket, true, 0
	}
	seconds := math.Ceil((1 - bucket.Tokens) / limit.RatePerSecond)
	if seconds < 1 {
		seconds = 1
	}
	return bucket, false, time.Duration(seconds) * time.Second
}

// Key returns a rate-limit key using identity first, then remote IP.
func Key(identity string, r *http.Request) string {
	identity = strings.TrimSpace(identity)
	if identity != "" {
		return "identity:" + identity
	}
	return "ip:" + RemoteIP(r)
}

// RemoteIP extracts the client IP from an HTTP request.
func RemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	if strings.TrimSpace(r.RemoteAddr) != "" {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return "unknown"
}
