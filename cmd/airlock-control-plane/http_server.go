package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

type namedHTTPServer struct {
	Name   string
	Addr   string
	Server *http.Server
	Serve  func() error
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func runHTTPServers(ctx context.Context, servers []namedHTTPServer) error {
	if len(servers) == 0 {
		return fmt.Errorf("no HTTP servers configured")
	}
	errCh := make(chan error, len(servers))
	var wg sync.WaitGroup
	for _, entry := range servers {
		entry := entry
		slog.Info("airlock-control-plane listener starting", "name", entry.Name, "addr", entry.Addr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := entry.Serve(); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("%s listener stopped: %w", entry.Name, err)
			}
		}()
	}

	var err error
	select {
	case err = <-errCh:
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var shutdownWG sync.WaitGroup
	for _, entry := range servers {
		entry := entry
		shutdownWG.Add(1)
		go func() {
			defer shutdownWG.Done()
			if shutdownErr := entry.Server.Shutdown(shutdownCtx); shutdownErr != nil {
				slog.Error("airlock-control-plane listener shutdown failed", "name", entry.Name, "error", shutdownErr)
			}
		}()
	}
	shutdownWG.Wait()
	wg.Wait()
	return err
}
