package adminapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminRouterRoutes(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   string
	}{
		{method: http.MethodGet, path: "/healthz", want: "health"},
		{method: http.MethodGet, path: "/readyz", want: "ready"},
		{method: http.MethodGet, path: "/v1/admin/policies", want: "policies"},
		{method: http.MethodGet, path: "/v1/admin/workloads", want: "workloads"},
		{method: http.MethodGet, path: "/v1/admin/proxies", want: "proxies"},
		{method: http.MethodGet, path: "/v1/admin/events", want: "events"},
	}

	router := NewRouter(Handlers{
		Health:        markerHandler("health"),
		Ready:         markerHandler("ready"),
		ListPolicies:  markerHandler("policies"),
		ListWorkloads: markerHandler("workloads"),
		ListProxies:   markerHandler("proxies"),
		ListEvents:    markerHandler("events"),
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
