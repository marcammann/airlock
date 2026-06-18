// Package egress contains request destination, rule matching, and rewrite
// helpers shared by proxy-worker transports.
package egress

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	airlockv1 "github.com/marcammann/airlock/api/v1alpha1"
	"github.com/marcammann/airlock/internal/netutil"
	workersecrets "github.com/marcammann/airlock/internal/proxyworker/secrets"
)

// Redacted is the placeholder used when secret values are removed from logs.
const Redacted = "[REDACTED]"

// CompiledPolicy is the worker policy format consumed by egress evaluators.
type CompiledPolicy = airlockv1.CompiledPolicy

// EgressRule is one outbound allow rule in a compiled policy.
type EgressRule = airlockv1.EgressRule

// RewriteRule is one request rewrite attached to an egress rule.
type RewriteRule = airlockv1.RewriteRule

// Header is a case-insensitive HTTP header name/value pair.
type Header struct {
	Name string
	// Value is the header value after any Airlock rewrite substitution.
	Value string
}

// Destination is the normalized target of an outbound request.
type Destination struct {
	Scheme string
	Host   string
	Port   uint16
	// PathAndQuery preserves the request path and raw query used for matching and telemetry.
	PathAndQuery string
}

// HostHeaderValue returns the authority value for this destination.
func (d Destination) HostHeaderValue() string {
	defaultPort := uint16(80)
	if d.Scheme == "https" {
		defaultPort = 443
	}
	if d.Port == defaultPort {
		return d.Host
	}
	return fmt.Sprintf("%s:%d", d.Host, d.Port)
}

// ValidationError reports one or more policy or rewrite validation failures.
type ValidationError struct {
	Problems []string
}

// Error formats the validation failures as a single message.
func (e ValidationError) Error() string {
	return strings.Join(e.Problems, "; ")
}

// Redactor tracks secret values that must be masked in logs.
type Redactor struct {
	values []string
}

// Add records a sensitive value to redact.
func (r *Redactor) Add(value string) {
	if value == "" {
		return
	}
	for _, known := range r.values {
		if known == value {
			return
		}
	}
	r.values = append(r.values, value)
}

// Redact replaces all known sensitive values in input with Redacted.
func (r *Redactor) Redact(input string) string {
	out := input
	for _, value := range r.values {
		out = strings.ReplaceAll(out, value, Redacted)
	}
	return out
}

// FindEgressRule returns the first policy rule that matches a destination.
func FindEgressRule(policy CompiledPolicy, destination Destination) *EgressRule {
	for i := range policy.Egress {
		rule := &policy.Egress[i]
		if strings.EqualFold(rule.Host, destination.Host) &&
			ruleSchemeMatches(*rule, destination) &&
			rulePortMatches(*rule, destination) {
			return rule
		}
	}
	return nil
}

func ruleSchemeMatches(rule EgressRule, destination Destination) bool {
	return rule.Scheme == "" || strings.EqualFold(rule.Scheme, destination.Scheme)
}

func rulePortMatches(rule EgressRule, destination Destination) bool {
	return rule.Port == 0 || rule.Port == uint32(destination.Port)
}

// ApplyRewrites mutates headers according to rewrite rules and resolved secrets.
func ApplyRewrites(headers *[]Header, rewrites []RewriteRule, secrets workersecrets.SecretProvider, redactor *Redactor) error {
	for _, rewrite := range rewrites {
		if rewrite.Target != "header" {
			return fmt.Errorf("unsupported rewrite target %q", rewrite.Target)
		}
		secret, err := secrets.Resolve(rewrite.ValueFrom)
		if err != nil {
			return err
		}
		redactor.Add(secret)
		value := secret
		if rewrite.ValueTemplate != "" {
			value = strings.ReplaceAll(rewrite.ValueTemplate, "{{secret}}", secret)
		}
		if strings.ContainsAny(value, "\r\n") {
			return ValidationError{Problems: []string{"rewrite value contains CRLF"}}
		}
		SetHeader(headers, rewrite.Name, value)
	}
	return nil
}

// DestinationFromHTTPRequest normalizes the target destination of an HTTP request.
func DestinationFromHTTPRequest(req *http.Request) (Destination, error) {
	scheme := req.URL.Scheme
	if scheme == "" {
		scheme = "http"
		if req.TLS != nil {
			scheme = "https"
		}
	}
	defaultPort := uint16(80)
	if scheme == "https" {
		defaultPort = 443
	}
	authority := req.URL.Host
	if authority == "" {
		authority = req.Host
	}
	host, port, err := netutil.SplitHostPort(authority, defaultPort)
	if err != nil {
		return Destination{}, err
	}
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	return Destination{Scheme: scheme, Host: host, Port: port, PathAndQuery: path}, nil
}

// HeadersFromHTTPRequest flattens request headers into Airlock's rewrite format.
func HeadersFromHTTPRequest(req *http.Request) []Header {
	headers := make([]Header, 0, len(req.Header))
	for name, values := range req.Header {
		for _, value := range values {
			headers = append(headers, Header{Name: name, Value: value})
		}
	}
	return headers
}

// ApplyHeadersToHTTPRequest replaces request headers with Airlock's rewrite format.
func ApplyHeadersToHTTPRequest(req *http.Request, headers []Header) {
	req.Header = http.Header{}
	for _, header := range headers {
		if strings.EqualFold(header.Name, "Host") {
			req.Host = header.Value
			continue
		}
		req.Header.Add(header.Name, header.Value)
	}
}

// DestinationFromHeaders normalizes a destination from HTTP or pseudo headers.
func DestinationFromHeaders(headers []Header) (Destination, error) {
	method, _ := HeaderValue(headers, ":method")
	return DestinationFromHeadersWithMethod(headers, method)
}

// DestinationFromHeadersWithMethod normalizes a destination using headers and method.
func DestinationFromHeadersWithMethod(headers []Header, method string) (Destination, error) {
	scheme, ok := HeaderValue(headers, ":scheme")
	if !ok {
		scheme = "http"
	}
	if strings.EqualFold(method, "CONNECT") {
		scheme = "https"
	}
	defaultPort := uint16(80)
	if scheme == "https" {
		defaultPort = 443
	}
	authority, ok := HeaderValue(headers, ":authority")
	if !ok {
		authority, ok = HeaderValue(headers, "Host")
	}
	if !ok {
		return Destination{}, fmt.Errorf(":authority or Host header is required")
	}
	host, port, err := netutil.SplitHostPort(authority, defaultPort)
	if err != nil {
		return Destination{}, err
	}
	path, ok := HeaderValue(headers, ":path")
	if !ok {
		path = "/"
	}
	return Destination{Scheme: scheme, Host: host, Port: port, PathAndQuery: path}, nil
}

// HeaderValue returns the first case-insensitive header value for name.
func HeaderValue(headers []Header, name string) (string, bool) {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			return header.Value, true
		}
	}
	return "", false
}

// SetHeader replaces all existing values for name with a single value.
func SetHeader(headers *[]Header, name, value string) {
	filtered := (*headers)[:0]
	for _, header := range *headers {
		if !strings.EqualFold(header.Name, name) {
			filtered = append(filtered, header)
		}
	}
	*headers = append(filtered, Header{Name: name, Value: value})
}

// DecisionFields returns structured fields used by event logging and telemetry.
func DecisionFields(method string, destination Destination, rule *EgressRule, extra map[string]string) map[string]string {
	fields := map[string]string{
		"destination": net.JoinHostPort(destination.Host, strconv.Itoa(int(destination.Port))),
	}
	if method != "" {
		fields["method"] = method
	}
	if rule != nil && rule.Name != "" {
		fields["rule"] = rule.Name
	}
	for key, value := range extra {
		if key == "" || value == "" {
			continue
		}
		fields[key] = value
	}
	return fields
}
