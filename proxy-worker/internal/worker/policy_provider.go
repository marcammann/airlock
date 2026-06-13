package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"gopkg.in/yaml.v3"
)

type LocalPolicyProvider struct {
	path string
}

func NewLocalPolicyProvider(path string) LocalPolicyProvider {
	return LocalPolicyProvider{path: path}
}

func (p LocalPolicyProvider) Load() (CompiledPolicy, error) {
	return LoadPolicyFile(p.path)
}

func LoadPolicyFile(path string) (CompiledPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CompiledPolicy{}, err
	}
	var policy AirlockPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return CompiledPolicy{}, err
	}
	return Compile(policy)
}

type ControlPlanePolicyProvider struct {
	baseURL          string
	workloadIdentity string
	devToken         string
}

func NewControlPlanePolicyProvider(baseURL, workloadIdentity, devToken string) ControlPlanePolicyProvider {
	return ControlPlanePolicyProvider{baseURL: baseURL, workloadIdentity: workloadIdentity, devToken: devToken}
}

func (p ControlPlanePolicyProvider) Load() (CompiledPolicy, error) {
	target, err := parseHTTPURL(p.baseURL)
	if err != nil {
		return CompiledPolicy{}, err
	}
	if target.scheme != "http" {
		return CompiledPolicy{}, fmt.Errorf("dev-token or unauthenticated control plane fetch requires an http:// control plane URL")
	}
	path := "/v1/policies/" + percentEncodePathSegment(p.workloadIdentity)
	body, err := httpGet(target, path, p.devToken)
	if err != nil {
		return CompiledPolicy{}, err
	}
	var policy CompiledPolicy
	if err := json.Unmarshal(body, &policy); err != nil {
		return CompiledPolicy{}, err
	}
	return policy, nil
}

func (p ControlPlanePolicyProvider) LoadSPIFFEMTLS(ctx context.Context, serverSPIFFEID, spiffeSocket string) (CompiledPolicy, error) {
	target, err := url.Parse(strings.TrimSpace(p.baseURL))
	if err != nil {
		return CompiledPolicy{}, err
	}
	if target.Scheme != "https" {
		return CompiledPolicy{}, fmt.Errorf("SPIFFE control-plane auth requires an https:// control-plane URL")
	}
	serverID, err := spiffeid.FromString(serverSPIFFEID)
	if err != nil {
		return CompiledPolicy{}, fmt.Errorf("parse control-plane SPIFFE ID: %w", err)
	}
	fmt.Fprintf(os.Stderr, "airlock-proxy-worker spiffe: requesting policy workload=%s control_plane_url=%s expected_server_id=%s\n", p.workloadIdentity, p.baseURL, serverSPIFFEID)
	var opts []workloadapi.X509SourceOption
	if strings.TrimSpace(spiffeSocket) != "" {
		opts = append(opts, workloadapi.WithClientOptions(workloadapi.WithAddr(spiffeSocket)))
	}
	source, err := workloadapi.NewX509Source(ctx, opts...)
	if err != nil {
		return CompiledPolicy{}, fmt.Errorf("create SPIFFE X509 source: %w", err)
	}
	defer source.Close()
	if svid, err := source.GetX509SVID(); err == nil {
		fmt.Fprintf(os.Stderr, "airlock-proxy-worker spiffe: selected_x509_svid=%s chain_len=%d source_initial_sync=complete\n", svid.ID, len(svid.Certificates))
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(serverID)),
		},
	}
	requestURL := strings.TrimRight(p.baseURL, "/") + "/v1/policies/" + percentEncodePathSegment(p.workloadIdentity)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return CompiledPolicy{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "airlock-proxy-worker/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return CompiledPolicy{}, fmt.Errorf("fetch policy over SPIFFE mTLS: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return CompiledPolicy{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return CompiledPolicy{}, fmt.Errorf("control plane returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	fmt.Fprintf(os.Stderr, "airlock-proxy-worker spiffe: policy fetch over mTLS succeeded bytes=%d\n", len(body))
	var policy CompiledPolicy
	if err := json.Unmarshal(body, &policy); err != nil {
		return CompiledPolicy{}, err
	}
	return policy, nil
}

func percentEncodePathSegment(value string) string {
	return strings.ReplaceAll(url.PathEscape(value), ":", "%3A")
}

type httpURL struct {
	scheme   string
	host     string
	port     uint16
	basePath string
}

func parseHTTPURL(raw string) (httpURL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return httpURL{}, err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return httpURL{}, fmt.Errorf("control plane URL must start with http:// or https://")
	}
	defaultPort := uint16(80)
	if parsed.Scheme == "https" {
		defaultPort = 443
	}
	host := parsed.Hostname()
	if host == "" {
		return httpURL{}, fmt.Errorf("control plane host is required")
	}
	port := defaultPort
	if parsed.Port() != "" {
		parsedPort, err := strconv.ParseUint(parsed.Port(), 10, 16)
		if err != nil {
			return httpURL{}, fmt.Errorf("control plane port is invalid")
		}
		port = uint16(parsedPort)
	}
	return httpURL{scheme: parsed.Scheme, host: host, port: port, basePath: parsed.EscapedPath()}, nil
}

func httpGet(target httpURL, path string, devToken string) ([]byte, error) {
	conn, err := net.Dial("tcp", net.JoinHostPort(target.host, strconv.Itoa(int(target.port))))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	fullPath := strings.TrimRight(target.basePath, "/") + path
	hostHeader := target.host
	defaultPort := uint16(80)
	if target.scheme == "https" {
		defaultPort = 443
	}
	if target.port != defaultPort {
		hostHeader = fmt.Sprintf("%s:%d", target.host, target.port)
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\nConnection: close\r\nUser-Agent: airlock-proxy-worker/0.1\r\n", fullPath, hostHeader)
	if devToken != "" {
		fmt.Fprintf(conn, "Authorization: Bearer %s\r\n", devToken)
	}
	fmt.Fprint(conn, "\r\n")
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	return readHTTPResponse(conn)
}

func readHTTPResponse(r io.Reader) ([]byte, error) {
	response, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	headerEnd := findHeaderEnd(response)
	if headerEnd < 0 {
		return nil, fmt.Errorf("control plane response missing headers")
	}
	headerText := string(response[:headerEnd])
	status, err := parseResponseStatus(headerText)
	if err != nil {
		return nil, err
	}
	body := response[headerEnd+4:]
	if status != 200 {
		return nil, fmt.Errorf("control plane returned HTTP %d: %s", status, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func parseResponseStatus(headerText string) (int, error) {
	line, _, _ := strings.Cut(headerText, "\r\n")
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0, fmt.Errorf("control plane response status is invalid")
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("control plane response status is invalid")
	}
	return status, nil
}
