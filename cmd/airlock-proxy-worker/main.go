// Package main is the Airlock proxy-worker binary entrypoint.
package main

import (
	"log/slog"
	"os"

	"github.com/marcammann/airlock/internal/app/proxyworker"
)

func main() {
	if err := proxyworker.Run(); err != nil {
		slog.Error("airlock-proxy-worker failed", "error", err)
		os.Exit(1)
	}
}
