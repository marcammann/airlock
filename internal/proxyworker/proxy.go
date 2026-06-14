package proxyworker

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const maxHeaderBytes = 64 * 1024

type ProxyServer struct {
	policy            CompiledPolicy
	secrets           SecretProvider
	log               *EventLog
	mitmCA            *CertificateAuthority
	upstreamTLSConfig *tls.Config
}

type ProxyServerOptions struct {
	MITMCA            *CertificateAuthority
	UpstreamTLSConfig *tls.Config
}

func NewProxyServer(policy CompiledPolicy, secrets SecretProvider, log *EventLog) *ProxyServer {
	return NewProxyServerWithOptions(policy, secrets, log, ProxyServerOptions{})
}

func NewProxyServerWithOptions(policy CompiledPolicy, secrets SecretProvider, log *EventLog, opts ProxyServerOptions) *ProxyServer {
	if log == nil {
		log = NewEventLog(io.Discard)
	}
	return &ProxyServer{
		policy:            policy,
		secrets:           secrets,
		log:               log,
		mitmCA:            opts.MITMCA,
		upstreamTLSConfig: opts.UpstreamTLSConfig,
	}
}

func (s *ProxyServer) Serve(listener net.Listener) error {
	return s.ServeLimit(listener, 0)
}

func (s *ProxyServer) ServeLimit(listener net.Listener, limit int) error {
	accepted := 0
	for {
		if limit > 0 && accepted >= limit {
			return nil
		}
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		accepted++
		go func() {
			if err := s.HandleClient(conn); err != nil {
				s.log.Record(fmt.Sprintf("request failed: %v", err))
			}
		}()
	}
}

func (s *ProxyServer) HandleClient(client net.Conn) error {
	defer client.Close()
	request, err := readRequest(client)
	if err != nil {
		writeSimpleResponse(client, 400, "Bad Request", []byte(err.Error()))
		return nil
	}

	if strings.EqualFold(request.Method, "CONNECT") {
		return s.handleConnect(client, request)
	}

	destination, err := request.Destination()
	if err != nil {
		writeSimpleResponse(client, 400, "Bad Request", []byte(err.Error()))
		return nil
	}
	return s.forwardRequest(client, request, destination)
}

func (s *ProxyServer) handleConnect(client net.Conn, connectRequest HTTPRequest) error {
	host, port, err := splitHostPort(connectRequest.Target, 443)
	if err != nil {
		writeSimpleResponse(client, 400, "Bad Request", []byte(err.Error()))
		return nil
	}
	destination := Destination{Scheme: "https", Host: host, Port: port, PathAndQuery: "/"}
	rule := FindEgressRule(s.policy, destination)
	if rule == nil {
		s.log.Record(fmt.Sprintf(
			"denied CONNECT policy=%s policy_version=%s destination=%s:%d",
			s.policy.PolicyName,
			s.policy.Version,
			destination.Host,
			destination.Port,
		))
		writeSimpleResponse(client, 403, "Forbidden", []byte("egress denied"))
		return nil
	}
	if s.mitmCA == nil {
		if len(rule.Rewrites) == 0 {
			return s.tunnelConnect(client, destination, rule)
		}
		writeSimpleResponse(client, 501, "Not Implemented", []byte("https intercept is not configured"))
		return nil
	}

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	leaf, err := s.mitmCA.LeafCertificate(destination.Host)
	if err != nil {
		return err
	}
	tlsClient := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		return err
	}

	request, err := readRequest(tlsClient)
	if err != nil {
		writeSimpleResponse(tlsClient, 400, "Bad Request", []byte(err.Error()))
		return nil
	}
	destination.PathAndQuery = request.Target
	if strings.HasPrefix(request.Target, "http://") || strings.HasPrefix(request.Target, "https://") {
		parsed, err := request.Destination()
		if err != nil {
			writeSimpleResponse(tlsClient, 400, "Bad Request", []byte(err.Error()))
			return nil
		}
		destination.PathAndQuery = parsed.PathAndQuery
	}
	if destination.PathAndQuery == "" {
		destination.PathAndQuery = "/"
	}
	return s.forwardRequest(tlsClient, request, destination)
}

func (s *ProxyServer) tunnelConnect(client net.Conn, destination Destination, rule *EgressRule) error {
	upstream, err := net.Dial("tcp", net.JoinHostPort(destination.Host, strconv.Itoa(int(destination.Port))))
	if err != nil {
		return err
	}
	defer upstream.Close()

	s.log.Record(fmt.Sprintf(
		"allowed CONNECT tunnel policy=%s policy_version=%s rule=%s destination=%s:%d",
		s.policy.PolicyName,
		s.policy.Version,
		rule.Name,
		destination.Host,
		destination.Port,
	))
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, client)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	return nil
}

func (s *ProxyServer) forwardRequest(client net.Conn, request HTTPRequest, destination Destination) error {
	var redactor Redactor
	rule := FindEgressRule(s.policy, destination)
	if rule == nil {
		s.log.Record(fmt.Sprintf(
			"denied request policy=%s policy_version=%s method=%s destination=%s:%d",
			s.policy.PolicyName,
			s.policy.Version,
			request.Method,
			destination.Host,
			destination.Port,
		))
		writeSimpleResponse(client, 403, "Forbidden", []byte("egress denied"))
		return nil
	}

	if err := ApplyRewrites(&request.Headers, rule.Rewrites, s.secrets, &redactor); err != nil {
		s.log.Record(fmt.Sprintf(
			"denied request policy=%s policy_version=%s rule=%s method=%s destination=%s:%d dependency=secret error=%v",
			s.policy.PolicyName,
			s.policy.Version,
			rule.Name,
			request.Method,
			destination.Host,
			destination.Port,
			err,
		))
		writeSimpleResponse(client, 502, "Bad Gateway", []byte("secret dependency unavailable"))
		return nil
	}
	deleteHeader(&request.Headers, "Proxy-Authorization")
	deleteHeader(&request.Headers, "Proxy-Connection")
	setHeader(&request.Headers, "Host", destination.HostHeaderValue())
	setHeader(&request.Headers, "Connection", "close")

	s.log.Record(redactor.Redact(fmt.Sprintf(
		"allowed request policy=%s policy_version=%s rule=%s method=%s destination=%s:%d headers=%+v",
		s.policy.PolicyName,
		s.policy.Version,
		rule.Name,
		request.Method,
		destination.Host,
		destination.Port,
		request.Headers,
	)))

	upstream, err := s.dialUpstream(destination)
	if err != nil {
		return err
	}
	defer upstream.Close()
	if _, err := upstream.Write(request.OriginFormBytes(destination)); err != nil {
		return err
	}
	if tcp, ok := upstream.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	response, err := io.ReadAll(upstream)
	if err != nil {
		return err
	}
	_, err = client.Write(response)
	return err
}

func (s *ProxyServer) dialUpstream(destination Destination) (net.Conn, error) {
	address := net.JoinHostPort(destination.Host, strconv.Itoa(int(destination.Port)))
	if destination.Scheme != "https" {
		return net.Dial("tcp", address)
	}
	config := &tls.Config{ServerName: destination.Host, MinVersion: tls.VersionTLS12}
	if s.upstreamTLSConfig != nil {
		config = s.upstreamTLSConfig.Clone()
		if config.ServerName == "" {
			config.ServerName = destination.Host
		}
	}
	return tls.Dial("tcp", address, config)
}

type Header struct {
	Name  string
	Value string
}

type Destination struct {
	Scheme       string
	Host         string
	Port         uint16
	PathAndQuery string
}

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

type HTTPRequest struct {
	Method  string
	Target  string
	Version string
	Headers []Header
	Body    []byte
}

func readRequest(r io.Reader) (HTTPRequest, error) {
	data, err := readHTTPRequestBytes(r)
	if err != nil {
		return HTTPRequest{}, err
	}
	headerEnd := findHeaderEnd(data)
	if headerEnd < 0 {
		return HTTPRequest{}, fmt.Errorf("request headers missing terminator")
	}
	head := string(data[:headerEnd])
	request, err := parseRequestHead(head)
	if err != nil {
		return HTTPRequest{}, err
	}
	request.Body = append(request.Body, data[headerEnd+4:]...)
	return request, nil
}

func (r HTTPRequest) Destination() (Destination, error) {
	if rest, ok := strings.CutPrefix(r.Target, "http://"); ok {
		return parseAbsoluteTarget("http", rest)
	}
	if rest, ok := strings.CutPrefix(r.Target, "https://"); ok {
		return parseAbsoluteTarget("https", rest)
	}
	host, ok := headerValue(r.Headers, "Host")
	if !ok {
		return Destination{}, fmt.Errorf("Host header is required")
	}
	hostName, port, err := splitHostPort(host, 80)
	if err != nil {
		return Destination{}, err
	}
	return Destination{Scheme: "http", Host: hostName, Port: port, PathAndQuery: r.Target}, nil
}

func (r HTTPRequest) OriginFormBytes(destination Destination) []byte {
	var out bytes.Buffer
	fmt.Fprintf(&out, "%s %s %s\r\n", r.Method, destination.PathAndQuery, r.Version)
	for _, header := range r.Headers {
		fmt.Fprintf(&out, "%s: %s\r\n", header.Name, header.Value)
	}
	out.WriteString("\r\n")
	out.Write(r.Body)
	return out.Bytes()
}

func DestinationFromHeaders(headers []Header) (Destination, error) {
	method, _ := headerValue(headers, ":method")
	return destinationFromHeaders(headers, method)
}

func destinationFromHeaders(headers []Header, method string) (Destination, error) {
	scheme, ok := headerValue(headers, ":scheme")
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
	authority, ok := headerValue(headers, ":authority")
	if !ok {
		authority, ok = headerValue(headers, "Host")
	}
	if !ok {
		return Destination{}, fmt.Errorf(":authority or Host header is required")
	}
	host, port, err := splitHostPort(authority, defaultPort)
	if err != nil {
		return Destination{}, err
	}
	path, ok := headerValue(headers, ":path")
	if !ok {
		path = "/"
	}
	return Destination{Scheme: scheme, Host: host, Port: port, PathAndQuery: path}, nil
}

func parseRequestHead(head string) (HTTPRequest, error) {
	lines := strings.Split(head, "\r\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return HTTPRequest{}, fmt.Errorf("request line is required")
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 3 {
		return HTTPRequest{}, fmt.Errorf("request line must contain method target version")
	}
	request := HTTPRequest{Method: parts[0], Target: parts[1], Version: parts[2]}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return HTTPRequest{}, fmt.Errorf("invalid header line %q", line)
		}
		request.Headers = append(request.Headers, Header{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
	}
	return request, nil
}

func parseAbsoluteTarget(scheme, rest string) (Destination, error) {
	authority, path, ok := strings.Cut(rest, "/")
	if ok {
		path = "/" + path
	} else {
		path = "/"
	}
	defaultPort := uint16(80)
	if scheme == "https" {
		defaultPort = 443
	}
	host, port, err := splitHostPort(authority, defaultPort)
	if err != nil {
		return Destination{}, err
	}
	return Destination{Scheme: scheme, Host: host, Port: port, PathAndQuery: path}, nil
}

func splitHostPort(authority string, defaultPort uint16) (string, uint16, error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", 0, fmt.Errorf("destination host is required")
	}
	host, portText, ok := strings.Cut(authority, ":")
	if ok && host != "" && allDigits(portText) {
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return "", 0, fmt.Errorf("destination port is invalid")
		}
		return host, uint16(port), nil
	}
	return authority, defaultPort, nil
}

func headerValue(headers []Header, name string) (string, bool) {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			return header.Value, true
		}
	}
	return "", false
}

func setHeader(headers *[]Header, name, value string) {
	filtered := (*headers)[:0]
	for _, header := range *headers {
		if !strings.EqualFold(header.Name, name) {
			filtered = append(filtered, header)
		}
	}
	*headers = append(filtered, Header{Name: name, Value: value})
}

func deleteHeader(headers *[]Header, name string) {
	filtered := (*headers)[:0]
	for _, header := range *headers {
		if !strings.EqualFold(header.Name, name) {
			filtered = append(filtered, header)
		}
	}
	*headers = filtered
}

func readHTTPRequestBytes(r io.Reader) ([]byte, error) {
	var buffer []byte
	tmp := make([]byte, 4096)
	headerEnd := -1
	for headerEnd < 0 {
		n, err := r.Read(tmp)
		if err != nil {
			if err == io.EOF && len(buffer) > 0 {
				break
			}
			return nil, err
		}
		if n == 0 {
			continue
		}
		buffer = append(buffer, tmp[:n]...)
		if len(buffer) > maxHeaderBytes {
			return nil, fmt.Errorf("request headers exceed limit")
		}
		headerEnd = findHeaderEnd(buffer)
	}
	if headerEnd < 0 {
		return nil, fmt.Errorf("request headers missing terminator")
	}
	contentLength := parseContentLength(buffer[:headerEnd])
	bodyStart := headerEnd + 4
	for len(buffer)-bodyStart < contentLength {
		n, err := r.Read(tmp)
		if err != nil {
			return nil, err
		}
		buffer = append(buffer, tmp[:n]...)
	}
	return buffer[:bodyStart+contentLength], nil
}

func parseContentLength(headerBytes []byte) int {
	for _, line := range strings.Split(string(headerBytes), "\r\n")[1:] {
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			length, _ := strconv.Atoi(strings.TrimSpace(value))
			return length
		}
	}
	return 0
}

func findHeaderEnd(data []byte) int {
	return bytes.Index(data, []byte("\r\n\r\n"))
}

func writeSimpleResponse(w io.Writer, status int, reason string, body []byte) {
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", status, reason, len(body))
	_, _ = w.Write(body)
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
