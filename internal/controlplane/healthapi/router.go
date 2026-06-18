// Package healthapi defines the shared control-plane health HTTP surface.
package healthapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Handlers contains the health handler functions.
type Handlers struct {
	Health http.HandlerFunc
	Ready  http.HandlerFunc
}

// NewRouter returns the shared health and readiness router.
func NewRouter(handlers Handlers) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Get("/healthz", handlers.Health)
	r.Get("/readyz", handlers.Ready)
	return r
}
