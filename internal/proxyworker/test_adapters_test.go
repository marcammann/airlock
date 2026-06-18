package proxyworker_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	airlockv1 "github.com/marcammann/airlock/api/v1alpha1"
	"github.com/marcammann/airlock/internal/proxyworker/builtin"
	"github.com/marcammann/airlock/internal/proxyworker/egress"
	"github.com/marcammann/airlock/internal/proxyworker/envoy"
	workerpolicy "github.com/marcammann/airlock/internal/proxyworker/policy"
	workersecrets "github.com/marcammann/airlock/internal/proxyworker/secrets"
	workertel "github.com/marcammann/airlock/internal/proxyworker/telemetry"
)

const APIVersion = airlockv1.APIVersion
const Redacted = egress.Redacted
const maxHeaderBytes = builtin.MaxHeaderBytes

type WorkloadIdentity = airlockv1.WorkloadIdentity
type PolicyRef = airlockv1.PolicyRef
type EgressRule = airlockv1.EgressRule
type RewriteRule = airlockv1.RewriteRule
type SecretRef = airlockv1.SecretRef
type CompiledPolicy = airlockv1.CompiledPolicy
type CompiledSecretProvider = airlockv1.CompiledSecretProvider
type CompiledVaultProvider = airlockv1.CompiledVaultProvider

type Header = egress.Header
type Destination = egress.Destination

type ProxyServer = builtin.ProxyServer
type ProxyServerOptions = builtin.ProxyServerOptions
type CertificateAuthority = builtin.CertificateAuthority

func NewProxyServer(policy CompiledPolicy, secrets workersecrets.SecretProvider, log *workertel.EventLog) *ProxyServer {
	return builtin.NewProxyServer(policy, secrets, log)
}

func NewProxyServerWithOptions(policy CompiledPolicy, secrets workersecrets.SecretProvider, log *workertel.EventLog, opts ProxyServerOptions) *ProxyServer {
	return builtin.NewProxyServerWithOptions(policy, secrets, log, opts)
}

func LoadCertificateAuthority(certPath, keyPath string) (*CertificateAuthority, error) {
	return builtin.LoadCertificateAuthority(certPath, keyPath)
}

func LoadTLSClientConfigWithRootCAs(certPath string) (*tls.Config, error) {
	return builtin.LoadTLSClientConfigWithRootCAs(certPath)
}

func ParseCertificateAuthority(certPEM, keyPEM []byte) (*CertificateAuthority, error) {
	return builtin.ParseCertificateAuthority(certPEM, keyPEM)
}

func GenerateCertificateAuthority(commonName string) ([]byte, []byte, error) {
	return builtin.GenerateCertificateAuthority(commonName)
}

type ExtProcDecision = envoy.ExtProcDecision
type ExtProcGRPCServer = envoy.ExtProcGRPCServer

func EvaluateExtProcHeaders(policy CompiledPolicy, requestHeaders []egress.Header, secrets workersecrets.SecretProvider, log *workertel.EventLog) (ExtProcDecision, error) {
	return envoy.EvaluateExtProcHeaders(policy, requestHeaders, secrets, log)
}

func EvaluateExtProcHeadersWithContext(ctx context.Context, policy CompiledPolicy, requestHeaders []egress.Header, secrets workersecrets.SecretProvider, log *workertel.EventLog) (ExtProcDecision, error) {
	return envoy.EvaluateExtProcHeadersWithContext(ctx, policy, requestHeaders, secrets, log)
}

func NewExtProcGRPCServer(policy CompiledPolicy, secrets workersecrets.SecretProvider, log *workertel.EventLog) (*ExtProcGRPCServer, error) {
	return envoy.NewExtProcGRPCServer(policy, secrets, log)
}

func ServeExtProc(ctx context.Context, listener net.Listener, policy CompiledPolicy, secrets workersecrets.SecretProvider, log *workertel.EventLog) error {
	return envoy.ServeExtProc(ctx, listener, policy, secrets, log)
}

type DecisionEvent = workertel.DecisionEvent
type DecisionKind = workertel.DecisionKind
type EventReporter = workertel.EventReporter
type EventReporterOptions = workertel.EventReporterOptions
type HeartbeatReporter = workertel.HeartbeatReporter
type HeartbeatReporterOptions = workertel.HeartbeatReporterOptions
type EventLogSnapshot = workertel.EventLogSnapshot

const (
	DecisionNone        = workertel.DecisionNone
	DecisionAllow       = workertel.DecisionAllow
	DecisionDeny        = workertel.DecisionDeny
	DecisionProxyError  = workertel.DecisionProxyError
	DecisionSecretError = workertel.DecisionSecretError
)

func NewEventLog(writer io.Writer) *workertel.EventLog {
	return workertel.NewEventLog(writer)
}

func NewMemoryEventLog() *workertel.EventLog {
	return workertel.NewMemoryEventLog()
}

func NewEventReporter(opts EventReporterOptions) (*EventReporter, error) {
	return workertel.NewEventReporter(opts)
}

func NewHeartbeatReporter(opts HeartbeatReporterOptions) (*HeartbeatReporter, error) {
	return workertel.NewHeartbeatReporter(opts)
}

func SourcePolicyByRule(policy CompiledPolicy) map[string]airlockv1.PolicyRef {
	return workertel.SourcePolicyByRule(policy)
}

type LocalPolicyProvider = workerpolicy.LocalPolicyProvider
type ControlPlanePolicyProvider = workerpolicy.ControlPlanePolicyProvider
type EnrollmentPolicyProvider = workerpolicy.EnrollmentPolicyProvider
type PolicyPollResult = workerpolicy.PolicyPollResult
type PolicyPoller = workerpolicy.PolicyPoller
type PolicyPollerOptions = workerpolicy.PolicyPollerOptions

func NewLocalPolicyProvider(path string) LocalPolicyProvider {
	return workerpolicy.NewLocalPolicyProvider(path)
}

func LoadPolicyFile(path string) (CompiledPolicy, error) {
	return workerpolicy.LoadPolicyFile(path)
}

func NewControlPlanePolicyProvider(baseURL, workloadIdentity string) ControlPlanePolicyProvider {
	return workerpolicy.NewControlPlanePolicyProvider(baseURL, workloadIdentity)
}

func NewEnrollmentPolicyProvider(baseURL, token string) EnrollmentPolicyProvider {
	return workerpolicy.NewEnrollmentPolicyProvider(baseURL, token)
}

func NewPolicyPoller(opts PolicyPollerOptions) (*PolicyPoller, error) {
	return workerpolicy.NewPolicyPoller(opts)
}

func NewSPIFFEMTLSHTTPClient(ctx context.Context, serverSPIFFEID, spiffeSocket string, timeout time.Duration) (*http.Client, io.Closer, error) {
	return workerpolicy.NewSPIFFEMTLSHTTPClient(ctx, serverSPIFFEID, spiffeSocket, timeout)
}

type SecretProvider = workersecrets.SecretProvider
type EnvFileSecretProvider = workersecrets.EnvFileSecretProvider
type EnvFileSecretProviderOptions = workersecrets.EnvFileSecretProviderOptions
type ReloadableSecretProvider = workersecrets.ReloadableSecretProvider

func NewEnvFileSecretProvider(opts EnvFileSecretProviderOptions) *EnvFileSecretProvider {
	return workersecrets.NewEnvFileSecretProvider(opts)
}

func NewReloadableSecretProvider(provider SecretProvider) *ReloadableSecretProvider {
	return workersecrets.NewReloadableSecretProvider(provider)
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

type eventReportPayload struct {
	Events []eventReportEvent `json:"events"`
}

type eventReportEvent struct {
	ID                     string                  `json:"id"`
	ObservedAt             time.Time               `json:"observedAt"`
	Type                   string                  `json:"type"`
	Severity               string                  `json:"severity"`
	Message                string                  `json:"message"`
	Count                  uint64                  `json:"count"`
	FirstObservedAt        time.Time               `json:"firstObservedAt"`
	LastObservedAt         time.Time               `json:"lastObservedAt"`
	ProxyID                string                  `json:"proxyId"`
	ProxyType              string                  `json:"proxyType,omitempty"`
	WorkloadIdentity       string                  `json:"workloadIdentity"`
	WorkloadName           string                  `json:"workloadName,omitempty"`
	WorkloadNamespace      string                  `json:"workloadNamespace,omitempty"`
	EffectivePolicyVersion string                  `json:"effectivePolicyVersion,omitempty"`
	SourcePolicyName       string                  `json:"sourcePolicyName,omitempty"`
	SourcePolicyNamespace  string                  `json:"sourcePolicyNamespace,omitempty"`
	Destination            *eventReportDestination `json:"destination,omitempty"`
	Reason                 string                  `json:"reason,omitempty"`
	Attributes             map[string]string       `json:"attributes,omitempty"`
}

type eventReportDestination struct {
	Scheme string `json:"scheme,omitempty"`
	Host   string `json:"host"`
	Port   uint32 `json:"port,omitempty"`
}
