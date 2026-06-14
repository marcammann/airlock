package controlplane

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marc/airlock/control-plane/internal/policy"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type AuthMode string

const (
	AuthModeNone     AuthMode = "none"
	AuthModeDevToken AuthMode = "dev-token"
	AuthModeSPIFFE   AuthMode = "spiffe"
	AuthModeOIDC     AuthMode = "oidc"
)

type Server struct {
	mu                       sync.RWMutex
	store                    *PolicyStore
	proxies                  map[string]proxyRecord
	events                   []AdminEvent
	eventIngestGlobalBucket  eventIngestBucket
	eventIngestBuckets       map[string]eventIngestBucket
	eventSuppressed          map[string]uint64
	workerAuthMode           AuthMode
	workerDevToken           string
	adminAuthMode            AuthMode
	adminDevToken            string
	adminOIDC                *OIDCAuthenticator
	adminRBAC                *RBACAuthorizer
	heartbeatStaleThreshold  int
	eventLogMode             EventLogMode
	eventLogLimit            int
	eventLogTTL              time.Duration
	eventIngestRate          float64
	eventIngestBurst         int
	eventIngestRatePerProxy  float64
	eventIngestBurstPerProxy int
	allowInsecureDevAuth     bool
	audit                    io.Writer
}

type ServerOptions struct {
	WorkerAuthMode           AuthMode
	WorkerDevToken           string
	AdminAuthMode            AuthMode
	AdminDevToken            string
	AdminOIDC                *OIDCAuthenticator
	AdminRBAC                *RBACAuthorizer
	HeartbeatStaleThreshold  int
	EventLogMode             EventLogMode
	EventLogLimit            int
	EventLogTTL              time.Duration
	EventIngestRate          float64
	EventIngestBurst         int
	EventIngestRatePerProxy  float64
	EventIngestBurstPerProxy int
	AllowInsecureDevAuth     bool
	Audit                    io.Writer
}

func NewServerWithOptions(store *PolicyStore, opts ServerOptions) *Server {
	audit := opts.Audit
	if audit == nil {
		audit = io.Discard
	}
	heartbeatStaleThreshold := opts.HeartbeatStaleThreshold
	if heartbeatStaleThreshold <= 0 {
		heartbeatStaleThreshold = 9
	}
	eventLogMode := opts.EventLogMode
	if eventLogMode == "" {
		eventLogMode = EventLogMemory
	}
	eventLogLimit := opts.EventLogLimit
	if eventLogLimit <= 0 {
		eventLogLimit = 1000
	}
	eventLogTTL := opts.EventLogTTL
	if eventLogTTL <= 0 {
		eventLogTTL = 24 * time.Hour
	}
	eventIngestRate := opts.EventIngestRate
	if eventIngestRate <= 0 {
		eventIngestRate = 100
	}
	eventIngestBurst := opts.EventIngestBurst
	if eventIngestBurst <= 0 {
		eventIngestBurst = 500
	}
	eventIngestRatePerProxy := opts.EventIngestRatePerProxy
	if eventIngestRatePerProxy <= 0 {
		eventIngestRatePerProxy = 2
	}
	eventIngestBurstPerProxy := opts.EventIngestBurstPerProxy
	if eventIngestBurstPerProxy <= 0 {
		eventIngestBurstPerProxy = 50
	}
	workerAuthMode := opts.WorkerAuthMode
	if workerAuthMode == "" {
		workerAuthMode = AuthModeNone
	}
	adminAuthMode := opts.AdminAuthMode
	if adminAuthMode == "" {
		adminAuthMode = AuthModeNone
	}
	return &Server{
		store:                    store,
		proxies:                  map[string]proxyRecord{},
		eventIngestBuckets:       map[string]eventIngestBucket{},
		eventSuppressed:          map[string]uint64{},
		workerAuthMode:           workerAuthMode,
		workerDevToken:           opts.WorkerDevToken,
		adminAuthMode:            adminAuthMode,
		adminDevToken:            opts.AdminDevToken,
		adminOIDC:                opts.AdminOIDC,
		adminRBAC:                opts.AdminRBAC,
		heartbeatStaleThreshold:  heartbeatStaleThreshold,
		eventLogMode:             eventLogMode,
		eventLogLimit:            eventLogLimit,
		eventLogTTL:              eventLogTTL,
		eventIngestRate:          eventIngestRate,
		eventIngestBurst:         eventIngestBurst,
		eventIngestRatePerProxy:  eventIngestRatePerProxy,
		eventIngestBurstPerProxy: eventIngestBurstPerProxy,
		allowInsecureDevAuth:     opts.AllowInsecureDevAuth,
		audit:                    audit,
	}
}

func (s *Server) WorkerHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("POST /v1/proxies/heartbeat", s.handleProxyHeartbeat)
	mux.HandleFunc("POST /v1/events", s.handleIngestEvents)
	mux.HandleFunc("GET /v1/policies/", s.handleGetPolicy)
	mux.HandleFunc("GET /v1/policies", s.handleGetPolicy)
	return mux
}

func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /v1/admin/policies", s.handleListAdminPolicies)
	mux.HandleFunc("GET /v1/admin/workloads", s.handleListAdminWorkloads)
	mux.HandleFunc("GET /v1/admin/proxies", s.handleListAdminProxies)
	mux.HandleFunc("GET /v1/admin/events", s.handleListAdminEvents)
	return mux
}

func (s *Server) HealthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.store == nil || s.store.Len() == 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ready": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ready": true, "policies": s.store.Len()})
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

	compiled, ok := s.getPolicy(workloadIdentity)
	if !ok {
		s.recordAudit(r, "get_policy", "not_found", workloadIdentity, authenticatedIdentity, nil)
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "policy not found"})
		return
	}

	s.recordAudit(r, "get_policy", "allowed", workloadIdentity, authenticatedIdentity, &compiled)
	writeJSON(w, http.StatusOK, compiled)
}

type AdminWorkloadsResponse struct {
	Workloads []AdminWorkloadSummary `json:"workloads"`
}

type AdminPoliciesResponse struct {
	Policies []AdminPolicySummary `json:"policies"`
}

type AdminPolicySummary struct {
	Name         string                     `json:"name"`
	Namespace    string                     `json:"namespace,omitempty"`
	Version      string                     `json:"version"`
	Egress       []AdminPolicyEgressSummary `json:"egress"`
	EgressCount  int                        `json:"egressCount"`
	RewriteCount int                        `json:"rewriteCount"`
	Source       string                     `json:"source"`
	ManagedBy    string                     `json:"managedBy"`
}

type AdminPolicyEgressSummary struct {
	Name         string `json:"name"`
	Scheme       string `json:"scheme"`
	Host         string `json:"host"`
	Port         uint32 `json:"port,omitempty"`
	RewriteCount int    `json:"rewriteCount"`
}

type AdminWorkloadSummary struct {
	Name            string                          `json:"name"`
	Namespace       string                          `json:"namespace,omitempty"`
	Version         string                          `json:"version"`
	Workload        policy.WorkloadIdentity         `json:"workload"`
	PolicyRefs      []policy.PolicyRef              `json:"policyRefs"`
	Egress          []AdminWorkloadEgressSummary    `json:"egress"`
	EgressCount     int                             `json:"egressCount"`
	RewriteCount    int                             `json:"rewriteCount"`
	SecretProvider  *AdminWorkloadSecretProviderRef `json:"secretProvider,omitempty"`
	Source          string                          `json:"source"`
	ManagedBy       string                          `json:"managedBy"`
	Status          string                          `json:"status"`
	InstanceCount   int                             `json:"instanceCount"`
	ActiveInstances int                             `json:"activeInstances"`
	LastHeartbeatAt *time.Time                      `json:"lastHeartbeatAt,omitempty"`
	LastDecisionAt  *time.Time                      `json:"lastDecisionAt,omitempty"`
	Decisions       DecisionCounts                  `json:"decisions"`
	Alerts          AlertCounts                     `json:"alerts"`
	Instances       []AdminProxyInstance            `json:"instances"`
}

type AdminWorkloadEgressSummary struct {
	Name         string `json:"name"`
	Scheme       string `json:"scheme"`
	Host         string `json:"host"`
	Port         uint32 `json:"port,omitempty"`
	RewriteCount int    `json:"rewriteCount"`
}

type AdminWorkloadSecretProviderRef struct {
	Provider string `json:"provider"`
}

type AdminProxiesResponse struct {
	Proxies []AdminProxyStatus `json:"proxies"`
	Source  string             `json:"source"`
}

type AdminProxyStatus struct {
	ID                string               `json:"id"`
	WorkloadIdentity  string               `json:"workloadIdentity"`
	WorkloadName      string               `json:"workloadName,omitempty"`
	EffectiveVersion  string               `json:"effectivePolicyVersion,omitempty"`
	ProxyType         string               `json:"proxyType,omitempty"`
	Status            string               `json:"status"`
	InstanceCount     int                  `json:"instanceCount"`
	ActiveInstances   int                  `json:"activeInstances"`
	LastPolicyFetchAt *time.Time           `json:"lastPolicyFetchAt,omitempty"`
	LastHeartbeatAt   *time.Time           `json:"lastHeartbeatAt,omitempty"`
	LastDecisionAt    *time.Time           `json:"lastDecisionAt,omitempty"`
	Decisions         DecisionCounts       `json:"decisions"`
	Instances         []AdminProxyInstance `json:"instances"`
}

type AdminProxyInstance struct {
	ID                string         `json:"id"`
	ProxyType         string         `json:"proxyType,omitempty"`
	PolicyFetched     bool           `json:"policyFetched"`
	HeartbeatInterval string         `json:"heartbeatInterval"`
	PodNamespace      string         `json:"podNamespace,omitempty"`
	PodName           string         `json:"podName,omitempty"`
	Status            string         `json:"status"`
	LastPolicyFetchAt *time.Time     `json:"lastPolicyFetchAt,omitempty"`
	LastHeartbeatAt   *time.Time     `json:"lastHeartbeatAt,omitempty"`
	LastDecisionAt    *time.Time     `json:"lastDecisionAt,omitempty"`
	Decisions         DecisionCounts `json:"decisions"`
}

type DecisionCounts struct {
	Allowed    uint64 `json:"allowed"`
	Denied     uint64 `json:"denied"`
	ProxyError uint64 `json:"proxyError"`
}

type AlertCounts struct {
	Denied     uint64 `json:"denied"`
	ProxyError uint64 `json:"proxyError"`
	Total      uint64 `json:"total"`
}

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

type proxyRecord struct {
	ProxyHeartbeatRequest
	LastHeartbeatAt time.Time
}

func (s *Server) handleListAdminPolicies(w http.ResponseWriter, r *http.Request) {
	auth := s.authorizedAdmin(r, AdminPermissionPolicyRead)
	if !auth.ok {
		s.recordAudit(r, "list_admin_policies", auth.outcome(), "", auth.identity, nil)
		writeJSON(w, auth.status(), map[string]any{"error": auth.outcome()})
		return
	}

	s.mu.RLock()
	var policies []policy.AirlockPolicy
	if s.store != nil {
		policies = s.store.AirlockPolicies()
	}
	s.mu.RUnlock()

	summaries := make([]AdminPolicySummary, 0, len(policies))
	for _, input := range policies {
		summaries = append(summaries, summarizeAirlockPolicy(input))
	}

	s.recordAudit(r, "list_admin_policies", "allowed", "", auth.identity, nil)
	writeJSON(w, http.StatusOK, AdminPoliciesResponse{Policies: summaries})
}

func (s *Server) handleListAdminWorkloads(w http.ResponseWriter, r *http.Request) {
	auth := s.authorizedAdmin(r, AdminPermissionPolicyRead)
	if !auth.ok {
		s.recordAudit(r, "list_admin_workloads", auth.outcome(), "", auth.identity, nil)
		writeJSON(w, auth.status(), map[string]any{"error": auth.outcome()})
		return
	}

	s.mu.RLock()
	var compiledPolicies []policy.CompiledPolicy
	workloadsByKey := map[string]policy.AirlockWorkload{}
	proxyRecords := make([]proxyRecord, 0, len(s.proxies))
	events := make([]AdminEvent, 0, len(s.events))
	if s.store != nil {
		compiledPolicies = s.store.Policies()
		for _, workload := range s.store.AirlockWorkloads() {
			workloadsByKey[workload.Spec.Workload.SPIFFEID] = workload
		}
	}
	for _, record := range s.proxies {
		proxyRecords = append(proxyRecords, record)
	}
	events = append(events, s.events...)
	s.mu.RUnlock()

	now := time.Now()
	instancesByWorkload := proxyInstancesByWorkload(proxyRecords, now, s.heartbeatStaleThreshold)
	alertsByWorkload := workloadAlertsByIdentity(events, now.Add(-24*time.Hour))
	summaries := make([]AdminWorkloadSummary, 0, len(compiledPolicies))
	for _, compiled := range compiledPolicies {
		summaries = append(summaries, summarizeWorkload(
			compiled,
			workloadsByKey[compiled.Workload.SPIFFEID],
			instancesByWorkload[compiled.Workload.SPIFFEID],
			alertsByWorkload[compiled.Workload.SPIFFEID],
		))
	}

	s.recordAudit(r, "list_admin_workloads", "allowed", "", auth.identity, nil)
	writeJSON(w, http.StatusOK, AdminWorkloadsResponse{Workloads: summaries})
}

func (s *Server) handleListAdminProxies(w http.ResponseWriter, r *http.Request) {
	auth := s.authorizedAdmin(r, AdminPermissionProxyRead)
	if !auth.ok {
		s.recordAudit(r, "list_admin_proxies", auth.outcome(), "", auth.identity, nil)
		writeJSON(w, auth.status(), map[string]any{"error": auth.outcome()})
		return
	}

	s.recordAudit(r, "list_admin_proxies", "allowed", "", auth.identity, nil)
	writeJSON(w, http.StatusOK, AdminProxiesResponse{
		Proxies: s.proxyStatuses(time.Now()),
		Source:  "control-plane-heartbeat",
	})
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

	s.mu.Lock()
	s.proxies[heartbeat.ID] = proxyRecord{
		ProxyHeartbeatRequest: heartbeat,
		LastHeartbeatAt:       time.Now().UTC(),
	}
	s.mu.Unlock()

	s.recordAudit(r, "proxy_heartbeat", "allowed", heartbeat.WorkloadIdentity, authenticatedIdentity, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) ReplaceStore(store *PolicyStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = store
}

func (s *Server) proxyStatuses(now time.Time) []AdminProxyStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	grouped := map[string]*AdminProxyStatus{}
	for _, record := range s.proxies {
		lastHeartbeatAt := record.LastHeartbeatAt
		heartbeatInterval, _ := time.ParseDuration(record.HeartbeatInterval)
		staleAfter := heartbeatInterval * time.Duration(s.heartbeatStaleThreshold)
		status := "active"
		if now.Sub(lastHeartbeatAt) > staleAfter {
			status = "stale"
		}
		groupID := proxyGroupID(record.ProxyHeartbeatRequest)
		group, ok := grouped[groupID]
		if !ok {
			group = &AdminProxyStatus{
				ID:               groupID,
				WorkloadIdentity: record.WorkloadIdentity,
				WorkloadName:     record.WorkloadName,
				EffectiveVersion: record.EffectiveVersion,
				ProxyType:        record.ProxyType,
				Status:           "stale",
			}
			grouped[groupID] = group
		}
		if status == "active" {
			group.Status = "active"
			group.ActiveInstances++
		}
		group.InstanceCount++
		group.Decisions.Allowed += record.Decisions.Allowed
		group.Decisions.Denied += record.Decisions.Denied
		group.Decisions.ProxyError += record.Decisions.ProxyError
		group.LastPolicyFetchAt = latestTimePtr(group.LastPolicyFetchAt, record.LastPolicyFetchAt)
		group.LastDecisionAt = latestTimePtr(group.LastDecisionAt, record.LastDecisionAt)
		group.LastHeartbeatAt = latestTimePtr(group.LastHeartbeatAt, &lastHeartbeatAt)
		group.Instances = append(group.Instances, AdminProxyInstance{
			ID:                record.ID,
			PolicyFetched:     record.PolicyFetched,
			HeartbeatInterval: record.HeartbeatInterval,
			PodNamespace:      record.PodNamespace,
			PodName:           record.PodName,
			Status:            status,
			LastPolicyFetchAt: record.LastPolicyFetchAt,
			LastHeartbeatAt:   &lastHeartbeatAt,
			LastDecisionAt:    record.LastDecisionAt,
			Decisions:         record.Decisions,
		})
	}
	out := make([]AdminProxyStatus, 0, len(grouped))
	for _, group := range grouped {
		sort.Slice(group.Instances, func(i int, j int) bool {
			return group.Instances[i].ID < group.Instances[j].ID
		})
		out = append(out, *group)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

func proxyGroupID(record ProxyHeartbeatRequest) string {
	parts := []string{
		strings.TrimSpace(record.WorkloadName),
		strings.TrimSpace(record.WorkloadIdentity),
		strings.TrimSpace(record.ProxyType),
	}
	compact := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			compact = append(compact, part)
		}
	}
	if len(compact) == 0 {
		return strings.TrimSpace(record.ID)
	}
	return strings.Join(compact, "|")
}

func proxyInstancesByWorkload(records []proxyRecord, now time.Time, staleThreshold int) map[string][]AdminProxyInstance {
	out := map[string][]AdminProxyInstance{}
	for _, record := range records {
		instance := proxyInstanceStatus(record, now, staleThreshold)
		out[record.WorkloadIdentity] = append(out[record.WorkloadIdentity], instance)
	}
	for workloadIdentity := range out {
		sort.Slice(out[workloadIdentity], func(i int, j int) bool {
			return out[workloadIdentity][i].ID < out[workloadIdentity][j].ID
		})
	}
	return out
}

func proxyInstanceStatus(record proxyRecord, now time.Time, staleThreshold int) AdminProxyInstance {
	lastHeartbeatAt := record.LastHeartbeatAt
	heartbeatInterval, _ := time.ParseDuration(record.HeartbeatInterval)
	staleAfter := heartbeatInterval * time.Duration(staleThreshold)
	status := "active"
	if now.Sub(lastHeartbeatAt) > staleAfter {
		status = "stale"
	}
	return AdminProxyInstance{
		ID:                record.ID,
		ProxyType:         record.ProxyType,
		PolicyFetched:     record.PolicyFetched,
		HeartbeatInterval: record.HeartbeatInterval,
		PodNamespace:      record.PodNamespace,
		PodName:           record.PodName,
		Status:            status,
		LastPolicyFetchAt: record.LastPolicyFetchAt,
		LastHeartbeatAt:   &lastHeartbeatAt,
		LastDecisionAt:    record.LastDecisionAt,
		Decisions:         record.Decisions,
	}
}

func workloadAlertsByIdentity(events []AdminEvent, since time.Time) map[string]AlertCounts {
	out := map[string]AlertCounts{}
	for _, event := range events {
		if event.ObservedAt.Before(since) {
			continue
		}
		count := event.Count
		if count == 0 {
			count = 1
		}
		counts := out[event.WorkloadIdentity]
		switch event.Type {
		case "egress.denied":
			counts.Denied += count
		case "proxy.error", "policy.fetch_failed", "secret.resolve_failed", "control_plane.auth_failed", "event.suppressed":
			counts.ProxyError += count
		default:
			continue
		}
		counts.Total += count
		out[event.WorkloadIdentity] = counts
	}
	return out
}

func latestTimePtr(left *time.Time, right *time.Time) *time.Time {
	if right == nil {
		return left
	}
	if left == nil || right.After(*left) {
		value := *right
		return &value
	}
	return left
}

func (s *Server) getPolicy(workloadIdentity string) (policy.CompiledPolicy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.store == nil {
		return policy.CompiledPolicy{}, false
	}
	return s.store.Get(workloadIdentity)
}

func (s *Server) authorized(r *http.Request, workloadIdentity string) (string, bool) {
	switch s.workerAuthMode {
	case AuthModeNone:
		return "", s.allowInsecureDevAuth
	case AuthModeDevToken:
		return "", s.allowInsecureDevAuth && r.Header.Get("Authorization") == "Bearer "+s.workerDevToken
	case AuthModeSPIFFE:
		id, ok := peerSPIFFEID(r)
		return id, ok && id == workloadIdentity
	default:
		return "", false
	}
}

type adminAuthorization struct {
	identity  string
	ok        bool
	forbidden bool
}

func (a adminAuthorization) status() int {
	if a.forbidden {
		return http.StatusForbidden
	}
	return http.StatusUnauthorized
}

func (a adminAuthorization) outcome() string {
	if a.forbidden {
		return "forbidden"
	}
	return "unauthorized"
}

func (s *Server) authorizedAdmin(r *http.Request, permission AdminPermission) adminAuthorization {
	switch s.adminAuthMode {
	case AuthModeNone:
		return adminAuthorization{ok: s.allowInsecureDevAuth}
	case AuthModeDevToken:
		return adminAuthorization{ok: s.allowInsecureDevAuth && r.Header.Get("Authorization") == "Bearer "+s.adminDevToken}
	case AuthModeSPIFFE:
		id, ok := peerSPIFFEID(r)
		return adminAuthorization{identity: id, ok: ok}
	case AuthModeOIDC:
		if s.adminOIDC == nil {
			return adminAuthorization{}
		}
		principal, err := s.adminOIDC.Authenticate(r.Context(), bearerToken(r))
		if err != nil {
			return adminAuthorization{}
		}
		identity := principalIdentifier(principal)
		if s.adminRBAC != nil && !s.adminRBAC.Authorize(principal, permission) {
			return adminAuthorization{identity: identity, forbidden: true}
		}
		return adminAuthorization{identity: identity, ok: true}
	default:
		return adminAuthorization{}
	}
}

func bearerToken(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	token, ok := strings.CutPrefix(value, "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(token)
}

func principalIdentifier(principal AdminPrincipal) string {
	if principal.Email != "" {
		return principal.Email
	}
	return principal.Subject
}

func summarizeAirlockPolicy(input policy.AirlockPolicy) AdminPolicySummary {
	summary := AdminPolicySummary{
		Name:        input.Metadata.Name,
		Namespace:   input.Metadata.Namespace,
		Version:     input.APIVersion,
		EgressCount: len(input.Spec.Egress),
		Source:      "control-plane-store",
		ManagedBy:   "read-only",
	}
	for _, rule := range input.Spec.Egress {
		rewriteCount := len(rule.Rewrites)
		summary.RewriteCount += rewriteCount
		summary.Egress = append(summary.Egress, AdminPolicyEgressSummary{
			Name:         rule.Name,
			Scheme:       rule.Scheme,
			Host:         rule.Host,
			Port:         rule.Port,
			RewriteCount: rewriteCount,
		})
	}
	return summary
}

func summarizeWorkload(compiled policy.CompiledPolicy, input policy.AirlockWorkload, instances []AdminProxyInstance, alerts AlertCounts) AdminWorkloadSummary {
	summary := AdminWorkloadSummary{
		Name:         compiled.PolicyName,
		Namespace:    input.Metadata.Namespace,
		Version:      compiled.Version,
		Workload:     compiled.Workload,
		EgressCount:  len(compiled.Egress),
		Source:       "control-plane-store",
		ManagedBy:    "read-only",
		RewriteCount: 0,
		Status:       "no_instances",
		Alerts:       alerts,
		Instances:    append([]AdminProxyInstance(nil), instances...),
	}
	summary.InstanceCount = len(summary.Instances)
	for _, instance := range summary.Instances {
		if instance.Status == "active" {
			summary.Status = "active"
			summary.ActiveInstances++
		}
		summary.Decisions.Allowed += instance.Decisions.Allowed
		summary.Decisions.Denied += instance.Decisions.Denied
		summary.Decisions.ProxyError += instance.Decisions.ProxyError
		summary.LastHeartbeatAt = latestTimePtr(summary.LastHeartbeatAt, instance.LastHeartbeatAt)
		summary.LastDecisionAt = latestTimePtr(summary.LastDecisionAt, instance.LastDecisionAt)
	}
	if summary.InstanceCount > 0 && summary.ActiveInstances == 0 {
		summary.Status = "stale"
	}
	if len(input.Spec.PolicyRefs) > 0 {
		summary.PolicyRefs = append([]policy.PolicyRef(nil), input.Spec.PolicyRefs...)
	} else {
		seen := map[string]struct{}{}
		for _, rule := range compiled.Egress {
			if rule.SourcePolicy == nil {
				continue
			}
			key := rule.SourcePolicy.Namespace + "/" + rule.SourcePolicy.Name
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			summary.PolicyRefs = append(summary.PolicyRefs, *rule.SourcePolicy)
		}
	}
	if compiled.SecretProvider != nil {
		summary.SecretProvider = &AdminWorkloadSecretProviderRef{Provider: compiled.SecretProvider.Provider}
	}
	for _, rule := range compiled.Egress {
		rewriteCount := len(rule.Rewrites)
		summary.RewriteCount += rewriteCount
		summary.Egress = append(summary.Egress, AdminWorkloadEgressSummary{
			Name:         rule.Name,
			Scheme:       rule.Scheme,
			Host:         rule.Host,
			Port:         rule.Port,
			RewriteCount: rewriteCount,
		})
	}
	return summary
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

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func peerSPIFFEID(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}

	id, err := x509svid.IDFromCert(r.TLS.PeerCertificates[0])
	if err != nil {
		return "", false
	}

	return id.String(), true
}

func (s *Server) recordAudit(r *http.Request, event string, outcome string, workloadIdentity string, authenticatedIdentity string, compiled *policy.CompiledPolicy) {
	record := map[string]any{
		"ts":                    time.Now().UTC().Format(time.RFC3339Nano),
		"event":                 event,
		"outcome":               outcome,
		"remoteAddr":            r.RemoteAddr,
		"workloadIdentity":      workloadIdentity,
		"authenticatedIdentity": authenticatedIdentity,
		"requestPath":           r.URL.Path,
		"requestUserAgent":      r.UserAgent(),
		"workerAuthMode":        string(s.workerAuthMode),
		"adminAuthMode":         string(s.adminAuthMode),
		"controlPlaneTrack":     "security",
	}
	if compiled != nil {
		record["workloadName"] = compiled.PolicyName
		record["effectivePolicyVersion"] = compiled.Version
	}

	_ = json.NewEncoder(s.audit).Encode(record)
}
