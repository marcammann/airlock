// Package workerapi defines the worker-facing control-plane HTTP surface.
package workerapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Handlers contains the worker API handler functions.
type Handlers struct {
	Health           http.HandlerFunc
	Ready            http.HandlerFunc
	ProxyHeartbeat   http.HandlerFunc
	IngestEvents     http.HandlerFunc
	CreateEnrollment http.HandlerFunc
	RedeemEnrollment http.HandlerFunc
	GetPolicy        http.HandlerFunc
}

// NewRouter returns the worker-facing API router.
func NewRouter(handlers Handlers) http.Handler {
	r := newRouter()
	r.Get("/healthz", handlers.Health)
	r.Get("/readyz", handlers.Ready)
	r.Post("/v1/proxies/heartbeat", handlers.ProxyHeartbeat)
	r.Post("/v1/events", handlers.IngestEvents)
	r.Post("/v1/enrollments", handlers.CreateEnrollment)
	r.Post("/v1/enrollments/redeem", handlers.RedeemEnrollment)
	r.Get("/v1/policies", handlers.GetPolicy)
	r.Get("/v1/policies/*", handlers.GetPolicy)
	return r
}

func newRouter() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	return r
}
