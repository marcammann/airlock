package telemetry

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var registerMetricsOnce sync.Once

var proxyDecisionsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "airlock_proxy_decisions_total",
		Help: "Total proxy decisions by kind.",
	},
	[]string{"kind"},
)

var proxyRequestDurationSeconds = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "airlock_proxy_request_duration_seconds",
		Help:    "Duration of builtin proxy requests.",
		Buckets: prometheus.DefBuckets,
	},
)

var secretResolveTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "airlock_secret_resolve_total",
		Help: "Total secret resolution attempts by provider and result.",
	},
	[]string{"provider", "result"},
)

var proxyActiveConnections = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "airlock_proxy_active_connections",
		Help: "Current number of active builtin proxy requests.",
	},
)

var controlPlaneEventsIngestedTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "airlock_cp_events_ingested_total",
		Help: "Total Airlock events accepted by the control plane.",
	},
)

var controlPlaneRequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "airlock_cp_requests_total",
		Help: "Total control-plane HTTP requests by surface and response code.",
	},
	[]string{"surface", "code"},
)

var controlPlaneAuthFailuresTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "airlock_cp_auth_failures_total",
		Help: "Total control-plane authentication or authorization failures by mode.",
	},
	[]string{"mode"},
)

var controlPlaneEventsDroppedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "airlock_cp_events_dropped_total",
		Help: "Total Airlock events dropped or suppressed by reason.",
	},
	[]string{"reason"},
)

var controlPlaneReconcileDurationSeconds = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "airlock_cp_reconcile_duration_seconds",
		Help:    "Duration of control-plane reconciliation by kind.",
		Buckets: prometheus.DefBuckets,
	},
	[]string{"kind"},
)

var controlPlaneActiveProxies = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "airlock_cp_active_proxies",
		Help: "Current number of active proxy instances tracked by the control plane.",
	},
)

// MetricsHandler returns the process Prometheus scrape handler.
func MetricsHandler() http.Handler {
	registerMetricsOnce.Do(func() {
		for _, kind := range []string{"allowed", "denied", "proxy_error", "secret_error"} {
			proxyDecisionsTotal.WithLabelValues(kind).Add(0)
		}
		controlPlaneEventsDroppedTotal.WithLabelValues("invalid").Add(0)
		controlPlaneEventsDroppedTotal.WithLabelValues("rate_limited").Add(0)
	})
	return promhttp.Handler()
}

// ProxyHTTPMetricsHandler records builtin proxy HTTP request metrics.
func ProxyHTTPMetricsHandler(next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedAt := time.Now()
		proxyActiveConnections.Inc()
		defer func() {
			proxyActiveConnections.Dec()
			proxyRequestDurationSeconds.Observe(time.Since(startedAt).Seconds())
		}()
		next.ServeHTTP(w, r)
	})
}

// ControlPlaneHTTPMetricsHandler records control-plane HTTP request metrics for a surface.
func ControlPlaneHTTPMetricsHandler(surface string, next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	if surface == "" {
		surface = "unknown"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		ObserveControlPlaneRequest(surface, recorder.status)
	})
}

// ObserveProxyDecision increments the proxy decision counter.
func ObserveProxyDecision(kind string) {
	if kind == "" {
		return
	}
	proxyDecisionsTotal.WithLabelValues(kind).Inc()
}

// ObserveSecretResolve increments the secret resolution counter.
func ObserveSecretResolve(provider string, result string) {
	if provider == "" {
		provider = "unknown"
	}
	if result == "" {
		result = "unknown"
	}
	secretResolveTotal.WithLabelValues(provider, result).Inc()
}

// ObserveControlPlaneRequest increments the control-plane request counter.
func ObserveControlPlaneRequest(surface string, status int) {
	if surface == "" {
		surface = "unknown"
	}
	if status <= 0 {
		status = http.StatusOK
	}
	controlPlaneRequestsTotal.WithLabelValues(surface, strconv.Itoa(status)).Inc()
}

// ObserveControlPlaneAuthFailure increments the control-plane auth failure counter.
func ObserveControlPlaneAuthFailure(mode string) {
	if mode == "" {
		mode = "unknown"
	}
	controlPlaneAuthFailuresTotal.WithLabelValues(mode).Inc()
}

// ObserveControlPlaneEventsIngested increments the accepted event counter.
func ObserveControlPlaneEventsIngested(count int) {
	if count <= 0 {
		return
	}
	controlPlaneEventsIngestedTotal.Add(float64(count))
}

// ObserveControlPlaneEventsDropped increments the dropped event counter.
func ObserveControlPlaneEventsDropped(reason string, count uint64) {
	if reason == "" || count == 0 {
		return
	}
	controlPlaneEventsDroppedTotal.WithLabelValues(reason).Add(float64(count))
}

// ObserveControlPlaneReconcileDuration records one control-plane reconcile duration.
func ObserveControlPlaneReconcileDuration(kind string, duration time.Duration) {
	if kind == "" || duration < 0 {
		return
	}
	controlPlaneReconcileDurationSeconds.WithLabelValues(kind).Observe(duration.Seconds())
}

// SetControlPlaneActiveProxies updates the active proxy gauge.
func SetControlPlaneActiveProxies(count int) {
	if count < 0 {
		count = 0
	}
	controlPlaneActiveProxies.Set(float64(count))
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.status = status
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(status)
}
