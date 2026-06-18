package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/marcammann/airlock/internal/controlplane/adminapi"
	"github.com/marcammann/airlock/internal/controlplane/healthapi"
	"github.com/marcammann/airlock/internal/controlplane/workerapi"
	"github.com/marcammann/airlock/internal/policy"
	"github.com/marcammann/airlock/internal/telemetry"
)

// AuthMode selects how the control plane authenticates a request surface.
type AuthMode string

const (
	// AuthModeNone disables authentication and is only valid with explicit insecure mode.
	AuthModeNone AuthMode = "none"
	// AuthModeSPIFFE authenticates requests with SPIFFE identities.
	AuthModeSPIFFE AuthMode = "spiffe"
	// AuthModeOIDC authenticates admin requests with OIDC bearer tokens.
	AuthModeOIDC AuthMode = "oidc"
	// AuthModeConfig authenticates requests using the configured auth chain.
	AuthModeConfig AuthMode = "config"
)

// Server owns control-plane state and exposes worker, admin, and health handlers.
type Server struct {
	mu                       sync.RWMutex
	store                    *PolicyStore
	proxies                  map[string]proxyRecord
	events                   []AdminEvent
	eventIngestGlobalBucket  eventIngestBucket
	eventIngestBuckets       map[string]eventIngestBucket
	eventSuppressed          map[string]uint64
	requestRateBuckets       map[string]requestRateBucket
	workerAuthMode           AuthMode
	adminAuthMode            AuthMode
	adminOIDC                *OIDCAuthenticator
	adminAuthenticator       *AuthenticatorChain
	adminRBAC                *RBACAuthorizer
	enrollmentAuthenticator  *AuthenticatorChain
	enrollmentAuthorizer     *EnrollmentAuthorizer
	enrollmentStore          *EnrollmentStore
	heartbeatStaleThreshold  int
	eventLogMode             EventLogMode
	eventLogLimit            int
	eventLogTTL              time.Duration
	eventIngestRate          float64
	eventIngestBurst         int
	eventIngestRatePerProxy  float64
	eventIngestBurstPerProxy int
	insecure                 bool
	audit                    io.Writer
}

// ServerOptions configures a control-plane server instance.
type ServerOptions struct {
	WorkerAuthMode           AuthMode
	AdminAuthMode            AuthMode
	AdminOIDC                *OIDCAuthenticator
	AdminAuthenticator       *AuthenticatorChain
	AdminRBAC                *RBACAuthorizer
	EnrollmentAuthenticator  *AuthenticatorChain
	EnrollmentAuthorizer     *EnrollmentAuthorizer
	EnrollmentStore          *EnrollmentStore
	EnrollmentDefaultTTL     time.Duration
	EnrollmentMaxTTL         time.Duration
	HeartbeatStaleThreshold  int
	EventLogMode             EventLogMode
	EventLogLimit            int
	EventLogTTL              time.Duration
	EventIngestRate          float64
	EventIngestBurst         int
	EventIngestRatePerProxy  float64
	EventIngestBurstPerProxy int
	Insecure                 bool
	Audit                    io.Writer
}

// NewServerWithOptions creates a control-plane server with explicit options.
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
	if opts.AdminAuthenticator != nil {
		adminAuthMode = AuthModeConfig
	}
	enrollmentStore := opts.EnrollmentStore
	if enrollmentStore == nil {
		enrollmentStore = NewEnrollmentStore(EnrollmentStoreOptions{
			DefaultTTL: opts.EnrollmentDefaultTTL,
			MaxTTL:     opts.EnrollmentMaxTTL,
		})
	}
	return &Server{
		store:                    store,
		proxies:                  map[string]proxyRecord{},
		eventIngestBuckets:       map[string]eventIngestBucket{},
		eventSuppressed:          map[string]uint64{},
		requestRateBuckets:       map[string]requestRateBucket{},
		workerAuthMode:           workerAuthMode,
		adminAuthMode:            adminAuthMode,
		adminOIDC:                opts.AdminOIDC,
		adminAuthenticator:       opts.AdminAuthenticator,
		adminRBAC:                opts.AdminRBAC,
		enrollmentAuthenticator:  opts.EnrollmentAuthenticator,
		enrollmentAuthorizer:     opts.EnrollmentAuthorizer,
		enrollmentStore:          enrollmentStore,
		heartbeatStaleThreshold:  heartbeatStaleThreshold,
		eventLogMode:             eventLogMode,
		eventLogLimit:            eventLogLimit,
		eventLogTTL:              eventLogTTL,
		eventIngestRate:          eventIngestRate,
		eventIngestBurst:         eventIngestBurst,
		eventIngestRatePerProxy:  eventIngestRatePerProxy,
		eventIngestBurstPerProxy: eventIngestBurstPerProxy,
		insecure:                 opts.Insecure,
		audit:                    audit,
	}
}

// WorkerHandler returns routes intended for proxy workers.
func (s *Server) WorkerHandler() http.Handler {
	return workerapi.NewRouter(workerapi.Handlers{
		Health:           s.handleHealth,
		Ready:            s.handleReady,
		ProxyHeartbeat:   s.handleProxyHeartbeat,
		IngestEvents:     s.handleIngestEvents,
		CreateEnrollment: s.handleCreateEnrollment,
		RedeemEnrollment: s.handleRedeemEnrollment,
		GetPolicy:        s.handleGetPolicy,
	})
}

// AdminHandler returns routes intended for the admin console and operators.
func (s *Server) AdminHandler() http.Handler {
	return adminapi.NewRouter(adminapi.Handlers{
		Health:        s.handleHealth,
		Ready:         s.handleReady,
		ListPolicies:  s.handleListAdminPolicies,
		ListWorkloads: s.handleListAdminWorkloads,
		ListProxies:   s.handleListAdminProxies,
		ListEvents:    s.handleListAdminEvents,
	})
}

// HealthHandler returns unauthenticated health and readiness routes.
func (s *Server) HealthHandler() http.Handler {
	return healthapi.NewRouter(healthapi.Handlers{
		Health: s.handleHealth,
		Ready:  s.handleReady,
	})
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

// ReplaceStore atomically swaps the policy store used by subsequent requests.
func (s *Server) ReplaceStore(store *PolicyStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = store
}

// RunMaintenance starts periodic cleanup for enrollments and runtime state.
func (s *Server) RunMaintenance(ctx context.Context) {
	if s.enrollmentStore != nil {
		go s.enrollmentStore.RunSweeper(ctx, time.Minute)
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.pruneRuntimeState(now.UTC())
		}
	}
}

func (s *Server) pruneRuntimeState(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneRuntimeStateLocked(now)
}

func (s *Server) pruneRuntimeStateLocked(now time.Time) {
	activeProxyIDs := map[string]struct{}{}
	for id, record := range s.proxies {
		heartbeatInterval, err := time.ParseDuration(record.HeartbeatInterval)
		if err != nil || heartbeatInterval <= 0 {
			heartbeatInterval = 10 * time.Second
		}
		pruneAfter := heartbeatInterval * time.Duration(s.heartbeatStaleThreshold*2)
		if now.Sub(record.LastHeartbeatAt) > pruneAfter {
			delete(s.proxies, id)
			continue
		}
		activeProxyIDs[id] = struct{}{}
	}
	for proxyID := range s.eventIngestBuckets {
		if _, ok := activeProxyIDs[proxyID]; !ok {
			delete(s.eventIngestBuckets, proxyID)
		}
	}
	for proxyID := range s.eventSuppressed {
		delete(s.eventSuppressed, proxyID)
	}
	for key, bucket := range s.requestRateBuckets {
		if now.Sub(bucket.Last) > requestRateBucketTTL {
			delete(s.requestRateBuckets, key)
		}
	}
	telemetry.SetControlPlaneActiveProxies(len(s.proxies))
}

func (s *Server) getPolicy(workloadIdentity string) (policy.CompiledPolicy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.store == nil {
		return policy.CompiledPolicy{}, false
	}
	return s.store.Get(workloadIdentity)
}

func (s *Server) compiledPolicyForWorkload(namespace string, name string) (policy.CompiledPolicy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.store == nil {
		return policy.CompiledPolicy{}, false
	}
	for _, workload := range s.store.AirlockWorkloads() {
		if workload.Metadata.Namespace == namespace && workload.Metadata.Name == name {
			return s.store.Get(workload.Spec.Workload.SPIFFEID)
		}
	}
	return policy.CompiledPolicy{}, false
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Error("write JSON response failed", "error", err)
	}
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

	if err := json.NewEncoder(s.audit).Encode(record); err != nil {
		slog.Error("write audit record failed", "error", err, "record", record)
	}
}
