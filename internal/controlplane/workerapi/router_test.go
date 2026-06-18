package workerapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWorkerRouterRoutes(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   string
	}{
		{method: http.MethodGet, path: "/healthz", want: "health"},
		{method: http.MethodGet, path: "/readyz", want: "ready"},
		{method: http.MethodPost, path: "/v1/proxies/heartbeat", want: "heartbeat"},
		{method: http.MethodPost, path: "/v1/events", want: "events"},
		{method: http.MethodPost, path: "/v1/enrollments", want: "create-enrollment"},
		{method: http.MethodPost, path: "/v1/enrollments/redeem", want: "redeem-enrollment"},
		{method: http.MethodGet, path: "/v1/policies", want: "policy"},
		{method: http.MethodGet, path: "/v1/policies/spiffe%3A%2F%2Fairlock.local%2Fns%2Fdemo%2Fsa%2Fapp", want: "policy"},
	}

	router := NewRouter(Handlers{
		Health:           markerHandler("health"),
		Ready:            markerHandler("ready"),
		ProxyHeartbeat:   markerHandler("heartbeat"),
		IngestEvents:     markerHandler("events"),
		CreateEnrollment: markerHandler("create-enrollment"),
		RedeemEnrollment: markerHandler("redeem-enrollment"),
		GetPolicy:        markerHandler("policy"),
	})
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(tt.method, tt.path, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", response.Code)
			}
			if got := response.Body.String(); got != tt.want {
				t.Fatalf("body = %q, want %q", got, tt.want)
			}
		})
	}
}

func markerHandler(value string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(value))
	}
}
