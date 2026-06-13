package controlplane

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
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
)

type Server struct {
	mu       sync.RWMutex
	store    *PolicyStore
	authMode AuthMode
	devToken string
	audit    io.Writer
}

func NewServer(store *PolicyStore, devToken string, audit io.Writer) *Server {
	authMode := AuthModeNone
	if devToken != "" {
		authMode = AuthModeDevToken
	}
	return NewServerWithAuth(store, authMode, devToken, audit)
}

func NewServerWithAuth(store *PolicyStore, authMode AuthMode, devToken string, audit io.Writer) *Server {
	if audit == nil {
		audit = io.Discard
	}
	return &Server{
		store:    store,
		authMode: authMode,
		devToken: devToken,
		audit:    audit,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /v1/admin/policies", s.handleListAdminPolicies)
	mux.HandleFunc("GET /v1/admin/proxies", s.handleListAdminProxies)
	mux.HandleFunc("GET /v1/policies/", s.handleGetPolicy)
	mux.HandleFunc("GET /v1/policies", s.handleGetPolicy)
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

type AdminPoliciesResponse struct {
	Policies []AdminPolicySummary `json:"policies"`
}

type AdminPolicySummary struct {
	Name           string                        `json:"name"`
	Version        string                        `json:"version"`
	Workload       policy.WorkloadIdentity       `json:"workload"`
	Egress         []AdminPolicyEgressSummary    `json:"egress"`
	EgressCount    int                           `json:"egressCount"`
	RewriteCount   int                           `json:"rewriteCount"`
	SecretProvider *AdminPolicySecretProviderRef `json:"secretProvider,omitempty"`
	Source         string                        `json:"source"`
	ManagedBy      string                        `json:"managedBy"`
}

type AdminPolicyEgressSummary struct {
	Name         string `json:"name"`
	Scheme       string `json:"scheme"`
	Host         string `json:"host"`
	Port         uint32 `json:"port,omitempty"`
	RewriteCount int    `json:"rewriteCount"`
}

type AdminPolicySecretProviderRef struct {
	Provider string `json:"provider"`
}

type AdminProxiesResponse struct {
	Proxies []AdminProxyStatus `json:"proxies"`
	Source  string             `json:"source"`
}

type AdminProxyStatus struct {
	ID                string     `json:"id"`
	WorkloadIdentity  string     `json:"workloadIdentity"`
	PolicyName        string     `json:"policyName,omitempty"`
	PolicyVersion     string     `json:"policyVersion,omitempty"`
	ProxyType         string     `json:"proxyType,omitempty"`
	PodNamespace      string     `json:"podNamespace,omitempty"`
	PodName           string     `json:"podName,omitempty"`
	Status            string     `json:"status"`
	LastPolicyFetchAt *time.Time `json:"lastPolicyFetchAt,omitempty"`
	LastHeartbeatAt   *time.Time `json:"lastHeartbeatAt,omitempty"`
}

func (s *Server) handleListAdminPolicies(w http.ResponseWriter, r *http.Request) {
	authenticatedIdentity, ok := s.authorizedAdmin(r)
	if !ok {
		s.recordAudit(r, "list_admin_policies", "unauthorized", "", authenticatedIdentity, nil)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	s.mu.RLock()
	var compiledPolicies []policy.CompiledPolicy
	if s.store != nil {
		compiledPolicies = s.store.Policies()
	}
	s.mu.RUnlock()

	summaries := make([]AdminPolicySummary, 0, len(compiledPolicies))
	for _, compiled := range compiledPolicies {
		summaries = append(summaries, summarizePolicy(compiled))
	}

	s.recordAudit(r, "list_admin_policies", "allowed", "", authenticatedIdentity, nil)
	writeJSON(w, http.StatusOK, AdminPoliciesResponse{Policies: summaries})
}

func (s *Server) handleListAdminProxies(w http.ResponseWriter, r *http.Request) {
	authenticatedIdentity, ok := s.authorizedAdmin(r)
	if !ok {
		s.recordAudit(r, "list_admin_proxies", "unauthorized", "", authenticatedIdentity, nil)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	s.recordAudit(r, "list_admin_proxies", "allowed", "", authenticatedIdentity, nil)
	writeJSON(w, http.StatusOK, AdminProxiesResponse{
		Proxies: []AdminProxyStatus{},
		Source:  "not-configured",
	})
}

func (s *Server) ReplaceStore(store *PolicyStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = store
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
	switch s.authMode {
	case AuthModeNone:
		return "", true
	case AuthModeDevToken:
		return "", r.Header.Get("Authorization") == "Bearer "+s.devToken
	case AuthModeSPIFFE:
		id, ok := peerSPIFFEID(r)
		return id, ok && id == workloadIdentity
	default:
		return "", false
	}
}

func (s *Server) authorizedAdmin(r *http.Request) (string, bool) {
	switch s.authMode {
	case AuthModeNone:
		return "", true
	case AuthModeDevToken:
		return "", r.Header.Get("Authorization") == "Bearer "+s.devToken
	case AuthModeSPIFFE:
		id, ok := peerSPIFFEID(r)
		return id, ok
	default:
		return "", false
	}
}

func summarizePolicy(compiled policy.CompiledPolicy) AdminPolicySummary {
	summary := AdminPolicySummary{
		Name:         compiled.PolicyName,
		Version:      compiled.Version,
		Workload:     compiled.Workload,
		EgressCount:  len(compiled.Egress),
		Source:       "control-plane-store",
		ManagedBy:    "read-only",
		RewriteCount: 0,
	}
	if compiled.SecretProvider != nil {
		summary.SecretProvider = &AdminPolicySecretProviderRef{Provider: compiled.SecretProvider.Provider}
	}
	for _, rule := range compiled.Egress {
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
		"authMode":              string(s.authMode),
		"controlPlaneTrack":     "security",
	}
	if compiled != nil {
		record["policyName"] = compiled.PolicyName
		record["policyVersion"] = compiled.Version
	}

	_ = json.NewEncoder(s.audit).Encode(record)
}
