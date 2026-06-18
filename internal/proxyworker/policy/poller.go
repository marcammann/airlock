package policy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	workertel "github.com/marcammann/airlock/internal/proxyworker/telemetry"
)

// PolicyPoller repeatedly fetches policies and applies changed versions.
type PolicyPoller struct {
	provider ControlPlanePolicyProvider
	client   *http.Client
	interval time.Duration
	etag     string
	log      *workertel.EventLog
	apply    func(context.Context, CompiledPolicy) error
}

// PolicyPollerOptions configures policy polling and reload callbacks.
type PolicyPollerOptions struct {
	Provider    ControlPlanePolicyProvider
	Client      *http.Client
	Interval    time.Duration
	InitialETag string
	Log         *workertel.EventLog
	Apply       func(context.Context, CompiledPolicy) error
}

// NewPolicyPoller validates options and creates a policy poller.
func NewPolicyPoller(opts PolicyPollerOptions) (*PolicyPoller, error) {
	if opts.Interval <= 0 {
		return nil, fmt.Errorf("policy poll interval must be greater than zero")
	}
	if opts.Apply == nil {
		return nil, fmt.Errorf("policy apply function is required")
	}
	return &PolicyPoller{
		provider: opts.Provider,
		client:   opts.Client,
		interval: opts.Interval,
		etag:     strings.TrimSpace(opts.InitialETag),
		log:      opts.Log,
		apply:    opts.Apply,
	}, nil
}

// Run polls until the context is canceled.
func (p *PolicyPoller) Run(ctx context.Context) {
	p.record(fmt.Sprintf("airlock-proxy-worker policy polling enabled interval=%s", p.interval))
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := p.Poll(ctx); err != nil {
				p.record(fmt.Sprintf("airlock-proxy-worker policy poll failed error=%q", err.Error()))
			}
		}
	}
}

// Poll performs one conditional fetch and applies the policy when it changed.
func (p *PolicyPoller) Poll(ctx context.Context) (bool, error) {
	result, err := p.provider.Poll(ctx, p.client, p.etag)
	if err != nil {
		return false, err
	}
	if result.NotModified {
		if result.ETag != "" {
			p.etag = result.ETag
		}
		return false, nil
	}
	if err := p.apply(ctx, result.Policy); err != nil {
		return false, err
	}
	p.etag = result.ETag
	p.record(fmt.Sprintf(
		"airlock-proxy-worker policy reloaded policy=%s policy_version=%s workload=%s etag=%s",
		result.Policy.PolicyName,
		result.Policy.Version,
		result.Policy.Workload.SPIFFEID,
		result.ETag,
	))
	return true, nil
}

func (p *PolicyPoller) record(message string) {
	if p.log != nil {
		p.log.Record(workertel.DecisionNone, message)
	}
}
