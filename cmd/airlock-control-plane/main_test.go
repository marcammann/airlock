package main

import (
	"strings"
	"testing"

	"github.com/marcammann/airlock/internal/controlplane"
)

func TestValidateAuthConfigRequiresExplicitInsecureDevMode(t *testing.T) {
	tests := []struct {
		name            string
		mode            controlplane.AuthMode
		token           string
		surface         string
		insecureDevMode bool
		wantErr         string
	}{
		{name: "spiffe worker", mode: controlplane.AuthModeSPIFFE, surface: "worker"},
		{name: "oidc admin", mode: controlplane.AuthModeOIDC, surface: "admin"},
		{name: "oidc worker", mode: controlplane.AuthModeOIDC, surface: "worker", wantErr: "worker auth mode oidc is not supported"},
		{name: "none without dev mode", mode: controlplane.AuthModeNone, surface: "worker", wantErr: "--insecure-dev-mode"},
		{name: "none with dev mode", mode: controlplane.AuthModeNone, surface: "worker", insecureDevMode: true},
		{name: "dev token without dev mode", mode: controlplane.AuthModeDevToken, token: "token", surface: "admin", wantErr: "--insecure-dev-mode"},
		{name: "dev token without token", mode: controlplane.AuthModeDevToken, surface: "admin", insecureDevMode: true, wantErr: "non-empty token"},
		{name: "dev token with dev mode", mode: controlplane.AuthModeDevToken, token: "token", surface: "admin", insecureDevMode: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuthConfig(tt.mode, tt.token, tt.surface, tt.insecureDevMode)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateAuthConfig() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateAuthConfig() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
