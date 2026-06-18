// Package main is the Airlock control-plane binary entrypoint.
package main

import (
	"log/slog"
	"os"

	"github.com/marcammann/airlock/internal/app/controlplane"
)

func main() {
	if err := controlplane.Run(); err != nil {
		slog.Error("airlock-control-plane failed", "error", err)
		os.Exit(1)
	}
}
