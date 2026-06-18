package builtin

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/marcammann/airlock/internal/netutil"
	airlockotel "github.com/marcammann/airlock/internal/otel"
	"github.com/marcammann/airlock/internal/proxyworker/egress"
	workersecrets "github.com/marcammann/airlock/internal/proxyworker/secrets"
	workertel "github.com/marcammann/airlock/internal/proxyworker/telemetry"
	"github.com/marcammann/airlock/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// MaxHeaderBytes is the maximum request header size accepted by proxy tests and helpers.
const MaxHeaderBytes = 64 * 1024
const defaultMaxResponseBytes = 16 << 20
const defaultUpstreamResponseHeaderTimeout = 10 * time.Second

var errResponseTooLarge = errors.New("upstream response too large")
var acceptTransparentConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept}

// ProxyServer serves Airlock's builtin HTTP proxy.
type ProxyServer struct {
	policy            CompiledPolicy
	policyPtr         atomic.Pointer[CompiledPolicy]
	secrets           workersecrets.SecretProvider
	log               *workertel.EventLog
	mitmCA            *CertificateAuthority
	upstreamTLSConfig *tls.Config
	maxResponseBytes  int64
	responseTimeout   time.Duration
}

// CompiledPolicy is the policy shape evaluated by the builtin proxy.
type CompiledPolicy = egress.CompiledPolicy

// EgressRule is an allow rule evaluated by the builtin proxy.
type EgressRule = egress.EgressRule

// Destination is a normalized upstream destination.
type Destination = egress.Destination

// ProxyServerOptions configures builtin proxy behavior.
type ProxyServerOptions struct {
	MITMCA                        *CertificateAuthority
	UpstreamTLSConfig             *tls.Config
	MaxResponseBytes              int64
	UpstreamResponseHeaderTimeout time.Duration
}

// NewProxyServer creates a builtin proxy with default options.
func NewProxyServer(policy CompiledPolicy, secrets workersecrets.SecretProvider, log *workertel.EventLog) *ProxyServer {
	return NewProxyServerWithOptions(policy, secrets, log, ProxyServerOptions{})
}

// NewProxyServerWithOptions creates a builtin proxy with explicit options.
func NewProxyServerWithOptions(policy CompiledPolicy, secrets workersecrets.SecretProvider, log *workertel.EventLog, opts ProxyServerOptions) *ProxyServer {
	if log == nil {
		log = workertel.NewEventLog(io.Discard)
	}
	maxResponseBytes := opts.MaxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = defaultMaxResponseBytes
	}
	responseTimeout := opts.UpstreamResponseHeaderTimeout
	if responseTimeout <= 0 {
		responseTimeout = defaultUpstreamResponseHeaderTimeout
	}
	server := &ProxyServer{
		policy:            policy,
		secrets:           secrets,
		log:               log,
		mitmCA:            opts.MITMCA,
		upstreamTLSConfig: opts.UpstreamTLSConfig,
		maxResponseBytes:  maxResponseBytes,
		responseTimeout:   responseTimeout,
	}
	server.UpdatePolicy(policy)
	return server
}

// UpdatePolicy swaps the policy used for new proxy requests.
func (s *ProxyServer) UpdatePolicy(policy CompiledPolicy) {
	policyCopy := policy
	s.policyPtr.Store(&policyCopy)
}

func (s *ProxyServer) currentPolicy() CompiledPolicy {
	policy := s.policyPtr.Load()
	if policy == nil {
		return s.policy
	}
	return *policy
}

// Serve accepts HTTP proxy connections until the context is canceled or the listener closes.
func (s *ProxyServer) Serve(ctx context.Context, listener net.Listener) error {
	httpServer := &http.Server{
		Handler:           telemetry.ProxyHTTPMetricsHandler(airlockotel.HTTPHandler("airlock.proxy", s.newGoProxyHandler(ctx))),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			_ = httpServer.Close()
		}
	}()
	err := httpServer.Serve(listener)
	if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

type goProxyRequestMetadata struct {
	Policy      CompiledPolicy
	Rule        *EgressRule
	Destination egress.Destination
	Method      string
}

func (s *ProxyServer) newGoProxyHandler(ctx context.Context) http.Handler {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Logger = log.New(io.Discard, "", 0)
	proxy.Verbose = false
	proxy.Tr = s.goProxyTransport()
	proxy.ConnectDial = func(network string, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
	}
	proxy.OnRequest().HandleConnectFunc(s.handleGoProxyConnect)
	proxy.OnRequest().DoFunc(s.handleGoProxyRequest)
	proxy.OnResponse().DoFunc(s.handleGoProxyResponse)
	return proxy
}

func (s *ProxyServer) goProxyTransport() *http.Transport {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.upstreamTLSConfig != nil {
		tlsConfig = s.upstreamTLSConfig.Clone()
	}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSClientConfig:       tlsConfig,
		DisableCompression:    true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: s.responseTimeout,
	}
}

func (s *ProxyServer) handleGoProxyConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	hostName, port, err := netutil.SplitHostPort(host, 443)
	if err != nil {
		return connectResponseAction(http.StatusBadRequest, err.Error()), host
	}
	destination := egress.Destination{Scheme: "https", Host: hostName, Port: port, PathAndQuery: "/"}
	setProxySpanAttributes(ctx, destination, "CONNECT", "")
	policy := s.currentPolicy()
	rule := egress.FindEgressRule(policy, destination)
	if rule == nil {
		setProxySpanAttributes(ctx, destination, "CONNECT", workertel.DecisionDeny)
		s.log.Record(workertel.DecisionDeny, fmt.Sprintf(
			"denied CONNECT policy=%s policy_version=%s destination=%s:%d",
			policy.PolicyName,
			policy.Version,
			destination.Host,
			destination.Port,
		), egress.DecisionFields("CONNECT", destination, nil, nil))
		return connectResponseAction(http.StatusForbidden, "egress denied"), host
	}
	if s.mitmCA == nil {
		if len(rule.Rewrites) == 0 {
			setProxySpanAttributes(ctx, destination, "CONNECT", workertel.DecisionAllow)
			s.log.Record(workertel.DecisionAllow, fmt.Sprintf(
				"allowed CONNECT tunnel policy=%s policy_version=%s rule=%s destination=%s:%d",
				policy.PolicyName,
				policy.Version,
				rule.Name,
				destination.Host,
				destination.Port,
			), egress.DecisionFields("CONNECT", destination, rule, nil))
			return acceptTransparentConnect, host
		}
		return connectResponseAction(http.StatusNotImplemented, "https intercept is not configured"), host
	}
	cert := s.mitmCA.TLSCertificate()
	return &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&cert)}, host
}

func connectResponseAction(status int, body string) *goproxy.ConnectAction {
	return &goproxy.ConnectAction{
		Action: goproxy.ConnectHijack,
		Hijack: func(_ *http.Request, client net.Conn, _ *goproxy.ProxyCtx) {
			writeSimpleResponse(client, status, http.StatusText(status), []byte(body))
			_ = client.Close()
		},
	}
}

func (s *ProxyServer) handleGoProxyRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	destination, err := egress.DestinationFromHTTPRequest(req)
	if err != nil {
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadRequest, err.Error())
	}
	setHTTPSpanAttributes(req, destination, req.Method, "")
	policy := s.currentPolicy()
	rule := egress.FindEgressRule(policy, destination)
	if rule == nil {
		setHTTPSpanAttributes(req, destination, req.Method, workertel.DecisionDeny)
		s.log.Record(workertel.DecisionDeny, egress.FormatDecisionLog("request", "denied", policy, nil, req.Method, destination, ""), egress.DecisionFields(req.Method, destination, nil, nil))
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "egress denied")
	}

	var redactor egress.Redactor
	headers := egress.HeadersFromHTTPRequest(req)
	if err := egress.ApplyRewrites(&headers, rule.Rewrites, s.secrets, &redactor); err != nil {
		setHTTPSpanAttributes(req, destination, req.Method, workertel.DecisionSecretError)
		s.log.Record(workertel.DecisionSecretError, egress.FormatDecisionLog("request", "denied", policy, rule, req.Method, destination, fmt.Sprintf("dependency=secret error=%v", err)), egress.DecisionFields(req.Method, destination, rule, map[string]string{"dependency": "secret", "reason": "secret_dependency_failed"}))
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway, "secret dependency unavailable")
	}
	egress.ApplyHeadersToHTTPRequest(req, headers)
	req.Host = destination.HostHeaderValue()
	if req.URL.Scheme == "" {
		req.URL.Scheme = destination.Scheme
	}
	if req.URL.Host == "" {
		req.URL.Host = destination.HostHeaderValue()
	}
	req = req.WithContext(context.WithoutCancel(req.Context()))
	req.RequestURI = ""
	ctx.UserData = goProxyRequestMetadata{Policy: policy, Rule: rule, Destination: destination, Method: req.Method}

	setHTTPSpanAttributes(req, destination, req.Method, workertel.DecisionAllow)
	s.log.Record(workertel.DecisionAllow, redactor.Redact(egress.FormatDecisionLog("request", "allowed", policy, rule, req.Method, destination, fmt.Sprintf("headers=%+v", headers))), egress.DecisionFields(req.Method, destination, rule, nil))
	return req, nil
}

func (s *ProxyServer) handleGoProxyResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp == nil {
		if ctx != nil && ctx.Error != nil {
			return s.handleGoProxyTransportError(ctx)
		}
		return nil
	}
	metadata, _ := ctx.UserData.(goProxyRequestMetadata)
	if metadata.Rule == nil {
		return resp
	}
	if resp.ContentLength > s.maxResponseBytes {
		s.recordHTTPResponseTooLarge(metadata)
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText, http.StatusBadGateway, "upstream response too large")
	}
	if resp.Body != nil {
		resp.Body = &maxReadCloser{
			ReadCloser: resp.Body,
			max:        s.maxResponseBytes,
			onExceeded: func() {
				s.recordHTTPResponseTooLarge(metadata)
			},
		}
	}
	return resp
}

func (s *ProxyServer) handleGoProxyTransportError(ctx *goproxy.ProxyCtx) *http.Response {
	metadata, _ := ctx.UserData.(goProxyRequestMetadata)
	status := http.StatusBadGateway
	reason := "upstream_dependency_failed"
	body := "upstream dependency unavailable"
	if isTimeoutError(ctx.Error) {
		status = http.StatusGatewayTimeout
		reason = "upstream_timeout"
		body = "upstream timed out"
	}
	if metadata.Rule != nil {
		s.log.Record(workertel.DecisionProxyError, fmt.Sprintf(
			"denied proxy_error policy=%s policy_version=%s rule=%s method=%s destination=%s:%d reason=%s error=%v",
			metadata.Policy.PolicyName,
			metadata.Policy.Version,
			metadata.Rule.Name,
			metadata.Method,
			metadata.Destination.Host,
			metadata.Destination.Port,
			reason,
			ctx.Error,
		), egress.DecisionFields(metadata.Method, metadata.Destination, metadata.Rule, map[string]string{"reason": reason}))
	}
	return goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText, status, body)
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (s *ProxyServer) recordHTTPResponseTooLarge(metadata goProxyRequestMetadata) {
	s.log.Record(workertel.DecisionProxyError, fmt.Sprintf(
		"denied proxy_error policy=%s policy_version=%s rule=%s method=%s destination=%s:%d reason=response_too_large",
		metadata.Policy.PolicyName,
		metadata.Policy.Version,
		metadata.Rule.Name,
		metadata.Method,
		metadata.Destination.Host,
		metadata.Destination.Port,
	), egress.DecisionFields(metadata.Method, metadata.Destination, metadata.Rule, map[string]string{"reason": "response_too_large"}))
}

type maxReadCloser struct {
	io.ReadCloser
	max        int64
	read       int64
	exceeded   atomic.Bool
	onExceeded func()
}

func (r *maxReadCloser) Read(p []byte) (int, error) {
	if r.exceeded.Load() {
		return 0, errResponseTooLarge
	}
	if len(p) == 0 {
		return 0, nil
	}
	remaining := r.max - r.read
	readLimit := int64(len(p))
	if readLimit > remaining+1 {
		readLimit = remaining + 1
	}
	if readLimit <= 0 {
		readLimit = 1
	}
	n, err := r.ReadCloser.Read(p[:readLimit])
	if int64(n) > remaining {
		r.read += remaining
		r.markExceeded()
		_ = r.Close()
		return int(remaining), errResponseTooLarge
	}
	r.read += int64(n)
	return n, err
}

func (r *maxReadCloser) markExceeded() {
	if r.exceeded.CompareAndSwap(false, true) && r.onExceeded != nil {
		r.onExceeded()
	}
}

func setProxySpanAttributes(proxyCtx *goproxy.ProxyCtx, destination Destination, method string, decision workertel.DecisionKind) {
	if proxyCtx == nil || proxyCtx.Req == nil {
		return
	}
	setHTTPSpanAttributes(proxyCtx.Req, destination, method, decision)
}

func setHTTPSpanAttributes(req *http.Request, destination Destination, method string, decision workertel.DecisionKind) {
	if req == nil {
		return
	}
	span := trace.SpanFromContext(req.Context())
	if !span.IsRecording() {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("egress.host", destination.Host),
		attribute.Int("egress.port", int(destination.Port)),
		attribute.String("egress.scheme", destination.Scheme),
		attribute.String("http.request.method", method),
	}
	if decision != workertel.DecisionNone {
		attrs = append(attrs, attribute.String("decision", string(decision)))
	}
	span.SetAttributes(attrs...)
}

func writeSimpleResponse(w io.Writer, status int, reason string, body []byte) {
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", status, reason, len(body))
	_, _ = w.Write(body)
}
