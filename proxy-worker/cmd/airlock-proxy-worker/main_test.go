package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
)

func TestParseProxyConfigDefaultsHTTPBuiltin(t *testing.T) {
	got, err := parseProxyConfig("http:builtin")
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != "http" || got.Mode != "builtin" || got.Listen != "127.0.0.1:18080" {
		t.Fatalf("config = %+v, want http:builtin default listen", got)
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

func TestRunControlPlaneOutageFailsBeforeStartup(t *testing.T) {
	controlPlaneURL := startFailingControlPlane(t)
	restoreFlags := replaceCommandLine(t, []string{
		"airlock-proxy-worker",
		"--proxy", "http:builtin@127.0.0.1:0",
		"--control-plane-url", controlPlaneURL,
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
		_, _ = io.Copy(io.Discard, conn)
		body := []byte(`{"error":"control plane unavailable"}`)
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body))
		_, _ = conn.Write(body)
	}()
	return "http://" + listener.Addr().String()
}
