package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoadProxyWorkerEnvParsesTypedValues(t *testing.T) {
	t.Setenv("AIRLOCK_PROXY", "http:builtin@127.0.0.1:18180")
	t.Setenv("AIRLOCK_NO_CONTROL_PLANE", "true")
	t.Setenv("AIRLOCK_POLICY_PATH", "/tmp/policy.yaml")
	t.Setenv("AIRLOCK_MAX_RESPONSE_BYTES", "1024")
	t.Setenv("AIRLOCK_EVENT_REPORT_RATE", "2.5")
	t.Setenv("AIRLOCK_EVENT_REPORT_FLUSH_INTERVAL", "250ms")
	t.Setenv("AIRLOCK_SPIFFE_SOCKET", "")
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/spire.sock")

	config, err := loadProxyWorkerEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Proxies) != 1 || config.Proxies[0] != "http:builtin@127.0.0.1:18180" {
		t.Fatalf("Proxies = %#v, want env proxy", config.Proxies)
	}
	if !config.NoControlPlane {
		t.Fatal("NoControlPlane = false, want true")
	}
	if config.PolicyPath != "/tmp/policy.yaml" {
		t.Fatalf("PolicyPath = %q, want /tmp/policy.yaml", config.PolicyPath)
	}
	if config.MaxResponseBytes != 1024 {
		t.Fatalf("MaxResponseBytes = %d, want 1024", config.MaxResponseBytes)
	}
	if config.EventReportRate != 2.5 {
		t.Fatalf("EventReportRate = %f, want 2.5", config.EventReportRate)
	}
	if config.EventReportFlushInterval != 250*time.Millisecond {
		t.Fatalf("EventReportFlushInterval = %s, want 250ms", config.EventReportFlushInterval)
	}
	if config.SPIFFESocket != "unix:///tmp/spire.sock" {
		t.Fatalf("SPIFFESocket = %q, want external SPIFFE endpoint socket", config.SPIFFESocket)
	}
}

func TestLoadProxyWorkerEnvRejectsInvalidTypedValue(t *testing.T) {
	t.Setenv("AIRLOCK_EVENT_REPORT_RATE", "not-a-float")

	if _, err := loadProxyWorkerEnv(); err == nil {
		t.Fatal("loadProxyWorkerEnv() error = nil, want invalid float error")
	}
}

func TestParseProxyConfigDefaultsHTTPBuiltin(t *testing.T) {
	got, err := parseProxyConfig("http:builtin")
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != "http" || got.Mode != "builtin" || got.Listen != "127.0.0.1:18080" {
		t.Fatalf("config = %+v, want http:builtin default listen", got)
	}
}

func TestParseProxyWorkerFlagsInfersEnrollmentAuth(t *testing.T) {
	restoreFlags := replaceCommandLine(t, []string{
		"airlock-proxy-worker",
		"--proxy", "http:builtin",
		"--enrollment-token", "al_enroll_test",
	})
	defer restoreFlags()

	got, err := parseProxyWorkerFlags(proxyWorkerEnv{ControlPlaneAuth: "spiffe"})
	if err != nil {
		t.Fatal(err)
	}
	if got.ControlPlaneAuth != "enrollment" {
		t.Fatalf("ControlPlaneAuth = %q, want enrollment", got.ControlPlaneAuth)
	}
	if got.ControlPlaneAuthExplicit {
		t.Fatal("ControlPlaneAuthExplicit = true, want false")
	}
	if got.Proxy.Mode != "builtin" || got.Proxy.Listen != "127.0.0.1:18080" {
		t.Fatalf("Proxy = %+v, want builtin default", got.Proxy)
	}
}

func TestParseProxyConfigDefaultsHTTPEnvoy(t *testing.T) {
	got, err := parseProxyConfig("http:envoy")
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != "http" || got.Mode != "envoy" || got.Listen != "127.0.0.1:50051" {
		t.Fatalf("config = %+v, want http:envoy default listen", got)
	}
}

func TestParseProxyConfigAcceptsExplicitListen(t *testing.T) {
	got, err := parseProxyConfig("http:builtin@127.0.0.1:18180")
	if err != nil {
		t.Fatal(err)
	}
	if got.Listen != "127.0.0.1:18180" {
		t.Fatalf("listen = %q, want explicit listen", got.Listen)
	}
}

func TestParseProxyConfigRejectsMalformedValue(t *testing.T) {
	_, err := parseProxyConfig("http")
	if err == nil {
		t.Fatal("parseProxyConfig() error = nil, want malformed proxy error")
	}
}

func TestResolveProxyConfigRequiresProxy(t *testing.T) {
	_, err := resolveProxyConfig(nil)
	if err == nil {
		t.Fatal("resolveProxyConfig() error = nil, want required --proxy error")
	}
}

func TestProxyIPIDPrefersPodIP(t *testing.T) {
	t.Setenv("POD_IP", "10.42.0.17")

	got, err := proxyIPID()
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.42.0.17" {
		t.Fatalf("proxyIPID() = %q, want POD_IP", got)
	}
}

func TestRunControlPlaneOutageFailsBeforeStartup(t *testing.T) {
	t.Setenv("AIRLOCK_PROXY", "")
	t.Setenv("AIRLOCK_NO_CONTROL_PLANE", "false")
	controlPlaneURL := startFailingControlPlane(t)
	restoreFlags := replaceCommandLine(t, []string{
		"airlock-proxy-worker",
		"--proxy", "http:builtin@127.0.0.1:0",
		"--control-plane-url", controlPlaneURL,
		"--insecure",
		"--workload-identity", "spiffe://airlock.local/ns/demo/sa/code-agent/component/airlock-proxy-worker",
	})
	defer restoreFlags()

	err := run()
	if err == nil {
		t.Fatal("run() error = nil, want control-plane outage error")
	}
	if !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("error = %q, want HTTP 503", err)
	}
}

func TestValidateControlPlaneAuth(t *testing.T) {
	tests := []struct {
		name            string
		auth            string
		authExplicit    bool
		enrollmentToken string
		enrollmentFile  string
		insecure        bool
		wantErr         string
	}{
		{name: "spiffe", auth: "spiffe"},
		{name: "spiffe default with enrollment token infers enrollment", auth: "spiffe", enrollmentToken: "token"},
		{name: "explicit spiffe with enrollment token is rejected", auth: "spiffe", authExplicit: true, enrollmentToken: "token", wantErr: "cannot be combined"},
		{name: "none string is rejected", auth: "none", wantErr: "--insecure"},
		{name: "insecure no auth", auth: "spiffe", insecure: true},
		{name: "insecure with explicit auth", auth: "spiffe", authExplicit: true, insecure: true, wantErr: "cannot be combined"},
		{name: "insecure with enrollment token", auth: "spiffe", enrollmentToken: "token", insecure: true, wantErr: "cannot use --enrollment-token"},
		{name: "enrollment without token", auth: "enrollment", wantErr: "--enrollment-token"},
		{name: "enrollment with token", auth: "enrollment", enrollmentToken: "token"},
		{name: "enrollment with file", auth: "enrollment", enrollmentFile: "/run/airlock/enrollment/token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateControlPlaneAuth(tt.auth, tt.authExplicit, tt.insecure, tt.enrollmentToken, tt.enrollmentFile)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateControlPlaneAuth() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateControlPlaneAuth() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func replaceCommandLine(t *testing.T, args []string) func() {
	t.Helper()
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = args
	return func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	}
}

func startFailingControlPlane(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		body := []byte(`{"error":"control plane unavailable"}`)
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body))
		_, _ = conn.Write(body)
	}()
	return "http://" + listener.Addr().String()
}
