package controlplane

import (
	"math"
	"net/http"
	"strconv"
	"time"

	controlratelimit "github.com/marcammann/airlock/internal/controlplane/ratelimit"
)

type requestRateLimit = controlratelimit.Limit
type requestRateBucket = controlratelimit.Bucket

var (
	policyFetchRateLimit      = requestRateLimit{RatePerSecond: 1, Burst: 60}
	heartbeatRateLimit        = requestRateLimit{RatePerSecond: 0.5, Burst: 30}
	enrollmentCreateRateLimit = requestRateLimit{RatePerSecond: 1.0 / 6.0, Burst: 10}
	enrollmentRedeemRateLimit = requestRateLimit{RatePerSecond: 0.5, Burst: 30}
	adminReadRateLimit        = requestRateLimit{RatePerSecond: 2, Burst: 120}
)

const requestRateBucketTTL = controlratelimit.BucketTTL

func (s *Server) allowAdminRead(w http.ResponseWriter, r *http.Request, auth adminAuthorization, auditAction string) bool {
	if s.allowRequest(w, r, "admin_read", rateLimitKey(auth.identity, r), adminReadRateLimit) {
		return true
	}
	s.recordAudit(r, auditAction, "rate_limited", "", auth.identity, nil)
	return false
}

func (s *Server) allowRequest(w http.ResponseWriter, r *http.Request, scope string, key string, limit requestRateLimit) bool {
	if key == "" {
		key = "unknown"
	}
	now := time.Now().UTC()
	s.mu.Lock()
	bucket, allowed, retryAfter := requestBucketAllow(s.requestRateBuckets[scope+"|"+key], limit, now)
	s.requestRateBuckets[scope+"|"+key] = bucket
	s.mu.Unlock()
	if allowed {
		return true
	}
	writeRateLimited(w, retryAfter)
	return false
}

func requestBucketAllow(bucket requestRateBucket, limit requestRateLimit, now time.Time) (requestRateBucket, bool, time.Duration) {
	return controlratelimit.Allow(bucket, limit, now)
}

func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(math.Ceil(retryAfter.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate_limited"})
}

func rateLimitKey(identity string, r *http.Request) string {
	return controlratelimit.Key(identity, r)
}

func remoteIP(r *http.Request) string {
	return controlratelimit.RemoteIP(r)
}
