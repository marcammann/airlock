package proxyworker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type HeartbeatReporter struct {
	baseURL           string
	devToken          string
	client            *http.Client
	proxyID           string
	proxyType         string
	workloadIdentity  string
	workloadName      string
	effectiveVersion  string
	policyFetched     bool
	policyFetchedAt   *time.Time
	heartbeatInterval time.Duration
	processStartedAt  time.Time
	log               *EventLog
}

type HeartbeatReporterOptions struct {
	BaseURL           string
	DevToken          string
	ProxyID           string
	ProxyType         string
	WorkloadIdentity  string
	WorkloadName      string
	EffectiveVersion  string
	PolicyFetchedAt   *time.Time
	HeartbeatInterval time.Duration
	ProcessStartedAt  time.Time
	Log               *EventLog
	Client            *http.Client
}

func NewHeartbeatReporter(opts HeartbeatReporterOptions) (*HeartbeatReporter, error) {
	if strings.TrimSpace(opts.BaseURL) == "" {
		return nil, fmt.Errorf("heartbeat base URL is required")
	}
	if strings.TrimSpace(opts.ProxyID) == "" {
		return nil, fmt.Errorf("heartbeat proxy ID is required")
	}
	if strings.TrimSpace(opts.WorkloadIdentity) == "" {
		return nil, fmt.Errorf("heartbeat workload identity is required")
	}
	if opts.HeartbeatInterval <= 0 {
		return nil, fmt.Errorf("heartbeat interval must be greater than zero")
	}
	if opts.ProcessStartedAt.IsZero() {
		opts.ProcessStartedAt = time.Now().UTC()
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &HeartbeatReporter{
		baseURL:           strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/"),
		devToken:          opts.DevToken,
		client:            client,
		proxyID:           opts.ProxyID,
		proxyType:         opts.ProxyType,
		workloadIdentity:  opts.WorkloadIdentity,
		workloadName:      opts.WorkloadName,
		effectiveVersion:  opts.EffectiveVersion,
		policyFetched:     opts.PolicyFetchedAt != nil,
		policyFetchedAt:   opts.PolicyFetchedAt,
		heartbeatInterval: opts.HeartbeatInterval,
		processStartedAt:  opts.ProcessStartedAt,
		log:               opts.Log,
	}, nil
}

func (r *HeartbeatReporter) Run(ctx context.Context) {
	r.record(fmt.Sprintf("airlock-proxy-worker heartbeat enabled proxy_id=%s workload=%s interval=%s control_plane=%s", r.proxyID, r.workloadIdentity, r.heartbeatInterval, r.baseURL))
	r.reportAndLog(ctx)
	ticker := time.NewTicker(r.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reportAndLog(ctx)
		}
	}
}

func (r *HeartbeatReporter) Report(ctx context.Context) error {
	snapshot := EventLogSnapshot{}
	if r.log != nil {
		snapshot = r.log.Snapshot()
	}
	payload := proxyHeartbeatPayload{
		ID:                r.proxyID,
		WorkloadIdentity:  r.workloadIdentity,
		WorkloadName:      r.workloadName,
		EffectiveVersion:  r.effectiveVersion,
		PolicyFetched:     r.policyFetched,
		ProxyType:         r.proxyType,
		HeartbeatInterval: r.heartbeatInterval.String(),
		PodNamespace:      os.Getenv("POD_NAMESPACE"),
		PodName:           os.Getenv("POD_NAME"),
		ProcessStartedAt:  &r.processStartedAt,
		LastPolicyFetchAt: r.policyFetchedAt,
		LastDecisionAt:    snapshot.LastDecisionAt,
		Decisions: decisionCountsPayload{
			Allowed:    snapshot.Allowed,
			Denied:     snapshot.Denied,
			ProxyError: snapshot.ProxyError,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+"/v1/proxies/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "airlock-proxy-worker/0.1")
	if r.devToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.devToken)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("heartbeat returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (r *HeartbeatReporter) reportAndLog(ctx context.Context) {
	if err := r.Report(ctx); err != nil {
		r.record(fmt.Sprintf("airlock-proxy-worker heartbeat failed proxy_id=%s error=%q", r.proxyID, err.Error()))
		return
	}
	r.record(fmt.Sprintf("airlock-proxy-worker heartbeat ok proxy_id=%s", r.proxyID))
}

func (r *HeartbeatReporter) record(message string) {
	if r.log != nil {
		r.log.Record(message)
	}
}

type proxyHeartbeatPayload struct {
	ID                string                `json:"id"`
	WorkloadIdentity  string                `json:"workloadIdentity"`
	WorkloadName      string                `json:"workloadName"`
	EffectiveVersion  string                `json:"effectivePolicyVersion"`
	PolicyFetched     bool                  `json:"policyFetched"`
	ProxyType         string                `json:"proxyType"`
	HeartbeatInterval string                `json:"heartbeatInterval"`
	PodNamespace      string                `json:"podNamespace,omitempty"`
	PodName           string                `json:"podName,omitempty"`
	ProcessStartedAt  *time.Time            `json:"processStartedAt,omitempty"`
	LastPolicyFetchAt *time.Time            `json:"lastPolicyFetchAt,omitempty"`
	LastDecisionAt    *time.Time            `json:"lastDecisionAt,omitempty"`
	Decisions         decisionCountsPayload `json:"decisions"`
}

type decisionCountsPayload struct {
	Allowed    uint64 `json:"allowed"`
	Denied     uint64 `json:"denied"`
	ProxyError uint64 `json:"proxyError"`
}
