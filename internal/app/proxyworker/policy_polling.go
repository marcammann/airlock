package proxyworker

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/marcammann/airlock/internal/proxyworker/egress"
	workerpolicy "github.com/marcammann/airlock/internal/proxyworker/policy"
	workersecrets "github.com/marcammann/airlock/internal/proxyworker/secrets"
	workertel "github.com/marcammann/airlock/internal/proxyworker/telemetry"
)

type policyUpdater interface {
	UpdatePolicy(egress.CompiledPolicy)
}

func startPolicyPoller(
	ctx context.Context,
	noControlPlane bool,
	controlPlaneAuth string,
	insecure bool,
	interval time.Duration,
	provider workerpolicy.ControlPlanePolicyProvider,
	client *http.Client,
	initialETag string,
	spiffeSocket string,
	secretFileRoot string,
	secrets *workersecrets.ReloadableSecretProvider,
	updater policyUpdater,
	eventReporter *workertel.EventReporter,
	heartbeatReporter *workertel.HeartbeatReporter,
	log *workertel.EventLog,
) {
	if noControlPlane || interval <= 0 || updater == nil {
		return
	}
	if !insecure && controlPlaneAuth != "spiffe" {
		if log != nil {
			log.Record(workertel.DecisionNone, "airlock-proxy-worker policy polling disabled reason=enrollment_auth_has_no_reusable_worker_credential")
		}
		return
	}
	poller, err := workerpolicy.NewPolicyPoller(workerpolicy.PolicyPollerOptions{
		Provider:    provider,
		Client:      client,
		Interval:    interval,
		InitialETag: initialETag,
		Log:         log,
		Apply: func(ctx context.Context, policy egress.CompiledPolicy) error {
			nextSecrets, err := workersecrets.NewSecretProviderForPolicy(ctx, policy, spiffeSocket, workersecrets.SecretProviderOptions{
				SecretFileRoot: secretFileRoot,
			})
			if err != nil {
				return err
			}
			secrets.Update(nextSecrets)
			updater.UpdatePolicy(policy)
			if eventReporter != nil {
				eventReporter.UpdatePolicy(policy)
			}
			if heartbeatReporter != nil {
				heartbeatReporter.UpdatePolicy(policy, time.Now().UTC())
			}
			return nil
		},
	})
	if err != nil {
		if log != nil {
			log.Record(workertel.DecisionNone, fmt.Sprintf("airlock-proxy-worker policy polling disabled error=%q", err.Error()))
		}
		return
	}
	go poller.Run(ctx)
}
