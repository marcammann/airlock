package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/marcammann/airlock/internal/controlplane"
	airlockotel "github.com/marcammann/airlock/internal/otel"
	"github.com/marcammann/airlock/internal/telemetry"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func newSPIFFEServer(ctx context.Context, listen string, socket string, trustDomain string, server *controlplane.Server) (*http.Server, func(), error) {
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socket)))
	if err != nil {
		return nil, nil, fmt.Errorf("create SPIFFE X509 source: %w", err)
	}

	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		source.Close()
		return nil, nil, fmt.Errorf("parse SPIFFE trust domain: %w", err)
	}

	httpServer := &http.Server{
		Addr:              listen,
		Handler:           telemetry.ControlPlaneHTTPMetricsHandler("worker", airlockotel.HTTPHandler("airlock.worker", server.WorkerHandler())),
		TLSConfig:         tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(td)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return httpServer, func() { source.Close() }, nil
}
