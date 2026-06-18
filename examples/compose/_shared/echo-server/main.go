// Package main runs the compose example echo server.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := os.Getenv("ECHO_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintf(w, "method=%s\n", r.Method)
			fmt.Fprintf(w, "host=%s\n", r.Host)
			fmt.Fprintf(w, "path=%s\n", r.URL.Path)
			fmt.Fprintf(w, "x-airlock-demo-secret=%s\n", r.Header.Get("X-Airlock-Demo-Secret"))
		}),
	}
	slog.Info("echo-server listening", "addr", addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("echo-server failed", "error", err)
		os.Exit(1)
	}
}
