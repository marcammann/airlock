package controlplane

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/marcammann/airlock/internal/policy"
)

// AdminWorkloadsResponse is returned by the admin workload listing endpoint.
type AdminWorkloadsResponse struct {
	Workloads []AdminWorkloadSummary `json:"workloads"`
}

// AdminPoliciesResponse is returned by the admin policy listing endpoint.
type AdminPoliciesResponse struct {
	Policies []AdminPolicySummary `json:"policies"`
}

// AdminPolicySummary is the admin-facing summary of one AirlockPolicy.
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

// AdminPolicyEgressSummary describes one egress rule in a policy summary.
type AdminPolicyEgressSummary struct {
	Name         string `json:"name"`
	Scheme       string `json:"scheme"`
	Host         string `json:"host"`
	Port         uint32 `json:"port,omitempty"`
	RewriteCount int    `json:"rewriteCount"`
}

// AdminWorkloadSummary is the admin-facing summary of one AirlockWorkload.
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

// AdminWorkloadEgressSummary describes one effective egress rule for a workload.
type AdminWorkloadEgressSummary struct {
	Name         string `json:"name"`
	Scheme       string `json:"scheme"`
	Host         string `json:"host"`
	Port         uint32 `json:"port,omitempty"`
	RewriteCount int    `json:"rewriteCount"`
}

// AdminWorkloadSecretProviderRef identifies the workload's secret provider type.
type AdminWorkloadSecretProviderRef struct {
	Provider string `json:"provider"`
}

// AdminProxiesResponse is returned by the legacy admin proxy listing endpoint.
type AdminProxiesResponse struct {
	Proxies []AdminProxyStatus `json:"proxies"`
	Source  string             `json:"source"`
}

// AdminProxyStatus summarizes proxy instances grouped by workload identity.
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

// AdminProxyInstance describes one live or recently seen proxy process.
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

// DecisionCounts contains proxy decision counters reported by workers.
type DecisionCounts struct {
	Allowed    uint64 `json:"allowed"`
	Denied     uint64 `json:"denied"`
	ProxyError uint64 `json:"proxyError"`
}

// AlertCounts contains denied/error counters used for workload alert summaries.
type AlertCounts struct {
	Denied     uint64 `json:"denied"`
	ProxyError uint64 `json:"proxyError"`
	Total      uint64 `json:"total"`
}

func (s *Server) handleListAdminPolicies(w http.ResponseWriter, r *http.Request) {
	auth := s.authorizedAdmin(r, AdminPermissionPolicyRead)
	if !auth.ok {
		s.recordAudit(r, "list_admin_policies", auth.outcome(), "", auth.identity, nil)
		writeJSON(w, auth.status(), map[string]any{"error": auth.outcome()})
		return
	}
	if !s.allowAdminRead(w, r, auth, "list_admin_policies") {
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
	auth := s.authorizedAdmin(r, AdminPermissionWorkloadRead)
	if !auth.ok {
		s.recordAudit(r, "list_admin_workloads", auth.outcome(), "", auth.identity, nil)
		writeJSON(w, auth.status(), map[string]any{"error": auth.outcome()})
		return
	}
	if !s.allowAdminRead(w, r, auth, "list_admin_workloads") {
		return
	}

	now := time.Now()
	s.mu.Lock()
	s.pruneRuntimeStateLocked(now.UTC())
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
	s.mu.Unlock()

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
	if !s.allowAdminRead(w, r, auth, "list_admin_proxies") {
		return
	}

	s.recordAudit(r, "list_admin_proxies", "allowed", "", auth.identity, nil)
	writeJSON(w, http.StatusOK, AdminProxiesResponse{
		Proxies: s.proxyStatuses(time.Now()),
		Source:  "control-plane-heartbeat",
	})
}

func (s *Server) proxyStatuses(now time.Time) []AdminProxyStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneRuntimeStateLocked(now)
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
		group.LastPolicyFetchAt = ptrMax(group.LastPolicyFetchAt, record.LastPolicyFetchAt, time.Time.After)
		group.LastDecisionAt = ptrMax(group.LastDecisionAt, record.LastDecisionAt, time.Time.After)
		group.LastHeartbeatAt = ptrMax(group.LastHeartbeatAt, &lastHeartbeatAt, time.Time.After)
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

func ptrMax[T any](left *T, right *T, greater func(T, T) bool) *T {
	if right == nil {
		return left
	}
	if left == nil || greater(*right, *left) {
		value := *right
		return &value
	}
	return left
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
		summary.LastHeartbeatAt = ptrMax(summary.LastHeartbeatAt, instance.LastHeartbeatAt, time.Time.After)
		summary.LastDecisionAt = ptrMax(summary.LastDecisionAt, instance.LastDecisionAt, time.Time.After)
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
