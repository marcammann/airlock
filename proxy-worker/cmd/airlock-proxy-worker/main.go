package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/marc/airlock/proxy-worker/internal/worker"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "airlock-proxy-worker: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		proxies              proxyFlags
		noControlPlane       = flag.Bool("no-control-plane", false, "load policy from --policy instead of the control plane")
		policyPath           = flag.String("policy", "", "local AirlockPolicy YAML path")
		mitmCACert           = flag.String("mitm-ca-cert", "", "public CA certificate used for HTTPS interception")
		mitmCAKey            = flag.String("mitm-ca-key", "", "private CA key used for HTTPS interception")
		upstreamCACert       = flag.String("upstream-ca-cert", "", "optional CA certificate bundle used to verify upstream TLS in builtin mode")
		controlPlaneURL      = flag.String("control-plane-url", "", "control-plane policy API URL")
		controlPlaneAuth     = flag.String("control-plane-auth", "none", "control-plane auth mode: none or dev-token")
		workloadIdentity     = flag.String("workload-identity", "", "workload SPIFFE ID")
		devToken             = flag.String("dev-token", "", "development bearer token for control-plane policy fetch")
		controlPlaneServerID = flag.String("control-plane-server-id", "", "reserved for SPIFFE control-plane auth")
		spiffeSocket         = flag.String("spiffe-socket", "", "reserved SPIFFE workload API socket URI")
	)
	flag.Var(&proxies, "proxy", "proxy listener in protocol:mode[@listen] form, for example http:builtin@127.0.0.1:18080")
	flag.Parse()

	proxyConfig, err := resolveProxyConfig(proxies)
	if err != nil {
		return err
	}
	if proxyConfig.Protocol != "http" || (proxyConfig.Mode != "builtin" && proxyConfig.Mode != "envoy") {
		return fmt.Errorf("Go worker currently supports --proxy http:builtin and --proxy http:envoy; %s:%s is the next parity slice", proxyConfig.Protocol, proxyConfig.Mode)
	}
	if proxyConfig.Mode == "envoy" && *upstreamCACert != "" {
		return fmt.Errorf("--upstream-ca-cert is for http:builtin; configure Envoy upstream TLS trust in the Envoy bootstrap")
	}

	var policy worker.CompiledPolicy
	ctx := context.Background()
	if *noControlPlane {
		if *policyPath == "" {
			return fmt.Errorf("--no-control-plane requires --policy")
		}
		if *controlPlaneURL != "" {
			return fmt.Errorf("--no-control-plane cannot use --control-plane-url")
		}
		policy, err = worker.NewLocalPolicyProvider(*policyPath).Load()
	} else {
		if *policyPath != "" {
			return fmt.Errorf("control-plane mode uses control-plane policy; remove --policy or add --no-control-plane")
		}
		if *controlPlaneURL == "" || *workloadIdentity == "" {
			return fmt.Errorf("control-plane mode requires --control-plane-url and --workload-identity")
		}
		provider := worker.NewControlPlanePolicyProvider(*controlPlaneURL, *workloadIdentity, "")
		if *controlPlaneAuth == "spiffe" {
			if *controlPlaneServerID == "" {
				return fmt.Errorf("--control-plane-auth spiffe requires --control-plane-server-id")
			}
			policy, err = provider.LoadSPIFFEMTLS(ctx, *controlPlaneServerID, *spiffeSocket)
		} else if *controlPlaneAuth == "dev-token" {
			provider = worker.NewControlPlanePolicyProvider(*controlPlaneURL, *workloadIdentity, *devToken)
			policy, err = provider.Load()
		} else if *controlPlaneAuth == "none" {
			policy, err = provider.Load()
		} else {
			return fmt.Errorf("unsupported control-plane auth %q; use none, dev-token, or spiffe", *controlPlaneAuth)
		}
	}
	if err != nil {
		return err
	}

	secrets, err := worker.NewSecretProviderForPolicy(ctx, policy, *spiffeSocket)
	if err != nil {
		return err
	}

	var mitmCA *worker.CertificateAuthority
	var upstreamTLSConfig *tls.Config
	if *mitmCACert != "" || *mitmCAKey != "" {
		if *mitmCACert == "" || *mitmCAKey == "" {
			return fmt.Errorf("--mitm-ca-cert and --mitm-ca-key must be set together")
		}
		mitmCA, err = worker.LoadCertificateAuthority(*mitmCACert, *mitmCAKey)
		if err != nil {
			return err
		}
	}
	if *upstreamCACert != "" {
		upstreamTLSConfig, err = worker.LoadTLSClientConfigWithRootCAs(*upstreamCACert)
		if err != nil {
			return err
		}
	}

	log := worker.NewStderrEventLog()
	log.Record(fmt.Sprintf(
		"airlock-proxy-worker loaded policy=%s policy_version=%s workload=%s proxy=%s:%s control_plane=%t https_intercept=%t",
		policy.PolicyName,
		policy.Version,
		policy.Workload.SPIFFEID,
		proxyConfig.Protocol,
		proxyConfig.Mode,
		!*noControlPlane,
		mitmCA != nil,
	))
	listener, err := net.Listen("tcp", proxyConfig.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	if proxyConfig.Mode == "envoy" {
		log.Record(fmt.Sprintf("airlock-proxy-worker envoy mode listening on %s", proxyConfig.Listen))
		return worker.ServeEnvoy(listener, policy, secrets, log, mitmCA)
	}
	log.Record(fmt.Sprintf("airlock-proxy-worker builtin proxy listening on %s", proxyConfig.Listen))
	return worker.NewProxyServerWithOptions(
		policy,
		secrets,
		log,
		worker.ProxyServerOptions{MITMCA: mitmCA, UpstreamTLSConfig: upstreamTLSConfig},
	).Serve(listener)
}

type proxyFlags []string

func (f *proxyFlags) String() string {
	return strings.Join(*f, ",")
}

func (f *proxyFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type proxyConfig struct {
	Protocol string
	Mode     string
	Listen   string
}

func resolveProxyConfig(flags proxyFlags) (proxyConfig, error) {
	if len(flags) == 0 {
		return proxyConfig{}, fmt.Errorf("--proxy is required; use protocol:mode[@listen], for example http:builtin@127.0.0.1:18080")
	}
	if len(flags) > 1 {
		return proxyConfig{}, fmt.Errorf("multiple --proxy values are not supported yet")
	}
	return parseProxyConfig(flags[0])
}

func parseProxyConfig(value string) (proxyConfig, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return proxyConfig{}, fmt.Errorf("--proxy cannot be empty")
	}
	protocolMode, listen, hasListen := strings.Cut(value, "@")
	protocol, mode, ok := strings.Cut(protocolMode, ":")
	if !ok || strings.TrimSpace(protocol) == "" || strings.TrimSpace(mode) == "" {
		return proxyConfig{}, fmt.Errorf("--proxy must use protocol:mode[@listen], got %q", value)
	}
	config := proxyConfig{
		Protocol: strings.TrimSpace(protocol),
		Mode:     strings.TrimSpace(mode),
	}
	if hasListen {
		if strings.TrimSpace(listen) == "" {
			return proxyConfig{}, fmt.Errorf("--proxy listen address cannot be empty")
		}
		config.Listen = strings.TrimSpace(listen)
	} else {
		switch config.Protocol + ":" + config.Mode {
		case "http:builtin":
			config.Listen = "127.0.0.1:18080"
		case "http:envoy":
			config.Listen = "127.0.0.1:50051"
		default:
			return proxyConfig{}, fmt.Errorf("no default listen address for --proxy %s:%s", config.Protocol, config.Mode)
		}
	}
	return config, nil
}
