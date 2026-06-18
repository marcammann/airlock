package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/marcammann/airlock/internal/policy"
	"github.com/marcammann/airlock/internal/telemetry"
)

// ProxyHeartbeatRequest is sent by workers to report liveness and counters.
type ProxyHeartbeatRequest struct {
	ID                string         `json:"id"`
	WorkloadIdentity  string         `json:"workloadIdentity"`
	WorkloadName      string         `json:"workloadName"`
	EffectiveVersion  string         `json:"effectivePolicyVersion"`
	PolicyFetched     bool           `json:"policyFetched"`
	ProxyType         string         `json:"proxyType"`
	HeartbeatInterval string         `json:"heartbeatInterval"`
	PodNamespace      string         `json:"podNamespace,omitempty"`
	PodName           string         `json:"podName,omitempty"`
	ProcessStartedAt  *time.Time     `json:"processStartedAt,omitempty"`
	LastPolicyFetchAt *time.Time     `json:"lastPolicyFetchAt,omitempty"`
	LastDecisionAt    *time.Time     `json:"lastDecisionAt,omitempty"`
	Decisions         DecisionCounts `json:"decisions"`
}

// CreateEnrollmentRequest asks the control plane to mint a workload token.
type CreateEnrollmentRequest struct {
	Workload   EnrollmentWorkloadRef `json:"workload"`
	TTLSeconds int                   `json:"ttlSeconds,omitempty"`
	Metadata   map[string]string     `json:"metadata,omitempty"`
}

// EnrollmentWorkloadRef identifies the workload receiving an enrollment token.
type EnrollmentWorkloadRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// CreateEnrollmentResponse contains a minted enrollment token and metadata.
type CreateEnrollmentResponse struct {
	Token             string    `json:"token"`
	ExpiresAt         time.Time `json:"expiresAt"`
	WorkloadIdentity  string    `json:"workloadIdentity"`
	WorkloadName      string    `json:"workloadName"`
	WorkloadNamespace string    `json:"workloadNamespace,omitempty"`
}

// RedeemEnrollmentResponse contains the policy returned for an enrollment token.
type RedeemEnrollmentResponse struct {
	Policy    policy.CompiledPolicy `json:"policy"`
	ExpiresAt time.Time             `json:"expiresAt"`
}

type proxyRecord struct {
	ProxyHeartbeatRequest
	LastHeartbeatAt time.Time
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	workloadIdentity, err := workloadIdentityFromRequest(r)
	if err != nil {
		s.recordAudit(r, "get_policy", "bad_request", "", "", nil)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	authenticatedIdentity, ok := s.authorized(r, workloadIdentity)
	if !ok {
		s.recordAudit(r, "get_policy", "unauthorized", workloadIdentity, authenticatedIdentity, nil)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	if !s.allowRequest(w, r, "policy_fetch", rateLimitKey(authenticatedIdentity, r), policyFetchRateLimit) {
		s.recordAudit(r, "get_policy", "rate_limited", workloadIdentity, authenticatedIdentity, nil)
		return
	}

	compiled, ok := s.getPolicy(workloadIdentity)
	if !ok {
		s.recordAudit(r, "get_policy", "not_found", workloadIdentity, authenticatedIdentity, nil)
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "policy not found"})
		return
	}
	etag := compiledPolicyETag(compiled)
	w.Header().Set("ETag", etag)
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		s.recordAudit(r, "get_policy", "not_modified", workloadIdentity, authenticatedIdentity, &compiled)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	s.recordAudit(r, "get_policy", "allowed", workloadIdentity, authenticatedIdentity, &compiled)
	writeJSON(w, http.StatusOK, compiled)
}

func (s *Server) handleCreateEnrollment(w http.ResponseWriter, r *http.Request) {
	var request CreateEnrollmentRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request); err != nil {
		s.recordAudit(r, "create_enrollment", "bad_request", "", "", nil)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid enrollment request"})
		return
	}
	request.Workload.Namespace = strings.TrimSpace(request.Workload.Namespace)
	request.Workload.Name = strings.TrimSpace(request.Workload.Name)
	if request.Workload.Namespace == "" || request.Workload.Name == "" {
		s.recordAudit(r, "create_enrollment", "bad_request", "", "", nil)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "workload namespace and name are required"})
		return
	}

	auth := s.authorizedEnrollment(r, request.Workload.Namespace, request.Workload.Name)
	if !auth.ok {
		s.recordAudit(r, "create_enrollment", auth.outcome(), "", auth.identity, nil)
		writeJSON(w, auth.status(), map[string]any{"error": auth.outcome()})
		return
	}
	if !s.allowRequest(w, r, "enrollment_create", rateLimitKey(auth.identity, r), enrollmentCreateRateLimit) {
		s.recordAudit(r, "create_enrollment", "rate_limited", "", auth.identity, nil)
		return
	}

	compiled, ok := s.compiledPolicyForWorkload(request.Workload.Namespace, request.Workload.Name)
	if !ok {
		s.recordAudit(r, "create_enrollment", "not_found", "", auth.identity, nil)
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "workload not found"})
		return
	}

	token, expiresAt, err := s.enrollmentStore.Mint(compiled, time.Duration(request.TTLSeconds)*time.Second, time.Now().UTC())
	if err != nil {
		s.recordAudit(r, "create_enrollment", "error", compiled.Workload.SPIFFEID, auth.identity, &compiled)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "create enrollment token"})
		return
	}

	s.recordAudit(r, "create_enrollment", "allowed", compiled.Workload.SPIFFEID, auth.identity, &compiled)
	writeJSON(w, http.StatusCreated, CreateEnrollmentResponse{
		Token:             token,
		ExpiresAt:         expiresAt,
		WorkloadIdentity:  compiled.Workload.SPIFFEID,
		WorkloadName:      compiled.PolicyName,
		WorkloadNamespace: request.Workload.Namespace,
	})
}

func (s *Server) handleRedeemEnrollment(w http.ResponseWriter, r *http.Request) {
	if !s.allowRequest(w, r, "enrollment_redeem", remoteIP(r), enrollmentRedeemRateLimit) {
		s.recordAudit(r, "redeem_enrollment", "rate_limited", "", "", nil)
		return
	}
	compiled, expiresAt, err := s.enrollmentStore.Redeem(bearerToken(r), time.Now().UTC())
	if err != nil {
		s.recordAudit(r, "redeem_enrollment", "unauthorized", "", "", nil)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	s.recordAudit(r, "redeem_enrollment", "allowed", compiled.Workload.SPIFFEID, "", &compiled)
	writeJSON(w, http.StatusOK, RedeemEnrollmentResponse{Policy: compiled, ExpiresAt: expiresAt})
}

func (s *Server) handleProxyHeartbeat(w http.ResponseWriter, r *http.Request) {
	var heartbeat ProxyHeartbeatRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&heartbeat); err != nil {
		s.recordAudit(r, "proxy_heartbeat", "bad_request", "", "", nil)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid heartbeat"})
		return
	}
	heartbeat.ID = strings.TrimSpace(heartbeat.ID)
	heartbeat.WorkloadIdentity = strings.TrimSpace(heartbeat.WorkloadIdentity)
	if heartbeat.ID == "" || heartbeat.WorkloadIdentity == "" {
		s.recordAudit(r, "proxy_heartbeat", "bad_request", heartbeat.WorkloadIdentity, "", nil)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id and workloadIdentity are required"})
		return
	}
	heartbeatInterval, err := time.ParseDuration(strings.TrimSpace(heartbeat.HeartbeatInterval))
	if err != nil || heartbeatInterval <= 0 {
		s.recordAudit(r, "proxy_heartbeat", "bad_request", heartbeat.WorkloadIdentity, "", nil)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "heartbeatInterval is required and must be a positive duration"})
		return
	}
	heartbeat.HeartbeatInterval = heartbeatInterval.String()

	authenticatedIdentity, ok := s.authorized(r, heartbeat.WorkloadIdentity)
	if !ok {
		s.recordAudit(r, "proxy_heartbeat", "unauthorized", heartbeat.WorkloadIdentity, authenticatedIdentity, nil)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	if !s.allowRequest(w, r, "proxy_heartbeat", rateLimitKey(authenticatedIdentity, r), heartbeatRateLimit) {
		s.recordAudit(r, "proxy_heartbeat", "rate_limited", heartbeat.WorkloadIdentity, authenticatedIdentity, nil)
		return
	}

	s.mu.Lock()
	s.pruneRuntimeStateLocked(time.Now().UTC())
	s.proxies[heartbeat.ID] = proxyRecord{
		ProxyHeartbeatRequest: heartbeat,
		LastHeartbeatAt:       time.Now().UTC(),
	}
	activeProxies := len(s.proxies)
	s.mu.Unlock()
	telemetry.SetControlPlaneActiveProxies(activeProxies)

	s.recordAudit(r, "proxy_heartbeat", "allowed", heartbeat.WorkloadIdentity, authenticatedIdentity, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func workloadIdentityFromRequest(r *http.Request) (string, error) {
	if value := strings.TrimSpace(r.URL.Query().Get("workload_identity")); value != "" {
		return value, nil
	}

	encoded := strings.TrimPrefix(r.URL.EscapedPath(), "/v1/policies/")
	encoded = strings.TrimSpace(encoded)
	if encoded == "" || encoded == r.URL.Path {
		return "", errBadWorkloadIdentity
	}

	decoded, err := url.PathUnescape(encoded)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(decoded) == "" {
		return "", errBadWorkloadIdentity
	}

	return decoded, nil
}

var errBadWorkloadIdentity = badRequestError("workload identity is required")

type badRequestError string

func (e badRequestError) Error() string {
	return string(e)
}

func compiledPolicyETag(policy policy.CompiledPolicy) string {
	data, err := json.Marshal(policy)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return `"sha256:` + hex.EncodeToString(sum[:]) + `"`
}

func etagMatches(header string, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "" || etag == "" {
		return false
	}
	for _, candidate := range strings.Split(header, ",") {
		if strings.TrimSpace(candidate) == etag {
			return true
		}
	}
	return false
}
