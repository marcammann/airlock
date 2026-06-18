package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConfigureTracingDisabledWithoutEndpoint(t *testing.T) {
	shutdown, err := ConfigureTracing(context.Background(), "airlock-test", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown() error = %v, want nil", err)
	}
}

func TestHTTPHandlerWrapsHandler(t *testing.T) {
	handler := HTTPHandler("airlock.test", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := response.Body.String(); got != "ok" {
		t.Fatalf("body = %q, want ok", got)
	}
}
