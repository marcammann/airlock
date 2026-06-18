package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/marcammann/airlock/internal/proxyworker/egress"
	workertel "github.com/marcammann/airlock/internal/proxyworker/telemetry"
)

type reporterSetupOptions struct {
	NoControlPlane           bool
	EventReport              string
	EventEndpoint            string
	ControlPlaneURL          string
	Proxy                    proxyConfig
	Policy                   egress.CompiledPolicy
	Insecure                 bool
	ControlPlaneAuth         string
	ControlPlaneClient       *http.Client
	HeartbeatInterval        time.Duration
	PolicyFetchedAt          *time.Time
	EventReportRate          float64
	EventReportBurst         int
	EventReportPendingLimit  int
	EventReportFlushInterval time.Duration
	Log                      *workertel.EventLog
	ProcessStartedAt         time.Time
}

type reporterSetupResult struct {
	ProxyID           string
	EventReporter     *workertel.EventReporter
	HeartbeatReporter *workertel.HeartbeatReporter
}

func startReporters(ctx context.Context, opts reporterSetupOptions) (reporterSetupResult, error) {
	eventReportMode := strings.TrimSpace(opts.EventReport)
	if eventReportMode == "" {
		eventReportMode = "control-plane"
	}
	if opts.NoControlPlane && eventReportMode == "control-plane" {
		eventReportMode = "disabled"
	}

	var result reporterSetupResult
	if !opts.NoControlPlane || eventReportMode != "disabled" {
		proxyID, err := proxyIPID()
		if err != nil {
			return reporterSetupResult{}, err
		}
		result.ProxyID = proxyID
	}

	switch eventReportMode {
	case "disabled":
	case "control-plane":
		if opts.NoControlPlane {
			return reporterSetupResult{}, fmt.Errorf("--event-report control-plane requires control-plane mode")
		}
		resolvedEndpoint := strings.TrimSpace(opts.EventEndpoint)
		if resolvedEndpoint == "" {
			resolvedEndpoint = strings.TrimRight(opts.ControlPlaneURL, "/") + "/v1/events"
		}
		eventOpts := workertel.EventReporterOptions{
			Endpoint:           resolvedEndpoint,
			ProxyID:            result.ProxyID,
			ProxyType:          opts.Proxy.Protocol + ":" + opts.Proxy.Mode,
			WorkloadIdentity:   opts.Policy.Workload.SPIFFEID,
			WorkloadName:       opts.Policy.PolicyName,
			WorkloadNamespace:  opts.Policy.Workload.Namespace,
			EffectiveVersion:   opts.Policy.Version,
			SourcePolicyByRule: workertel.SourcePolicyByRule(opts.Policy),
			RatePerSecond:      opts.EventReportRate,
			Burst:              opts.EventReportBurst,
			MaxPendingKeys:     opts.EventReportPendingLimit,
			FlushInterval:      opts.EventReportFlushInterval,
		}
		if !opts.Insecure && opts.ControlPlaneAuth == "spiffe" {
			eventOpts.Client = opts.ControlPlaneClient
		}
		reporter, err := workertel.NewEventReporter(eventOpts)
		if err != nil {
			return reporterSetupResult{}, err
		}
		result.EventReporter = reporter
		opts.Log.SetDecisionSink(reporter)
		go reporter.Run(ctx)
	default:
		return reporterSetupResult{}, fmt.Errorf("--event-report must be control-plane or disabled")
	}

	if !opts.NoControlPlane && opts.HeartbeatInterval > 0 {
		heartbeatOpts := workertel.HeartbeatReporterOptions{
			BaseURL:           opts.ControlPlaneURL,
			ProxyID:           result.ProxyID,
			ProxyType:         opts.Proxy.Protocol + ":" + opts.Proxy.Mode,
			WorkloadIdentity:  opts.Policy.Workload.SPIFFEID,
			WorkloadName:      opts.Policy.PolicyName,
			EffectiveVersion:  opts.Policy.Version,
			PolicyFetchedAt:   opts.PolicyFetchedAt,
			HeartbeatInterval: opts.HeartbeatInterval,
			ProcessStartedAt:  opts.ProcessStartedAt,
			Log:               opts.Log,
		}
		if !opts.Insecure && opts.ControlPlaneAuth == "spiffe" {
			heartbeatOpts.Client = opts.ControlPlaneClient
		}
		reporter, err := workertel.NewHeartbeatReporter(heartbeatOpts)
		if err != nil {
			return reporterSetupResult{}, err
		}
		result.HeartbeatReporter = reporter
		go reporter.Run(ctx)
	}

	return result, nil
}

func proxyIPID() (string, error) {
	if podIP := strings.TrimSpace(os.Getenv("POD_IP")); podIP != "" {
		return podIP, nil
	}
	if ip := firstNonLoopbackIP(); ip != "" {
		return ip, nil
	}
	return "", fmt.Errorf("proxy heartbeat requires POD_IP or a non-loopback pod/container IP address")
}

func firstNonLoopbackIP() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			if ipv4 := ip.To4(); ipv4 != nil {
				return ipv4.String()
			}
		}
	}
	return ""
}
