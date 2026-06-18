// Package adminapi defines the admin-facing control-plane HTTP surface.
package adminapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Handlers contains the admin API handler functions.
type Handlers struct {
	Health        http.HandlerFunc
	Ready         http.HandlerFunc
	ListPolicies  http.HandlerFunc
	ListWorkloads http.HandlerFunc
	ListProxies   http.HandlerFunc
	ListEvents    http.HandlerFunc
}

// NewRouter returns the admin-facing API router.
func NewRouter(handlers Handlers) http.Handler {
	r := newRouter()
	r.Get("/healthz", handlers.Health)
	r.Get("/readyz", handlers.Ready)
	r.Get("/v1/admin/policies", handlers.ListPolicies)
	r.Get("/v1/admin/workloads", handlers.ListWorkloads)
	r.Get("/v1/admin/proxies", handlers.ListProxies)
	r.Get("/v1/admin/events", handlers.ListEvents)
	return r
}

func newRouter() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	return r
}
