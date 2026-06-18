package healthapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthRouterRoutes(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{path: "/healthz", want: "health"},
		{path: "/readyz", want: "ready"},
	}

	router := NewRouter(Handlers{
		Health: markerHandler("health"),
		Ready:  markerHandler("ready"),
	})
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, tt.path, nil))
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
