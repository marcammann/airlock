package vaultpath

import (
	"strings"
	"testing"
)

func TestCleanKV2SecretPath(t *testing.T) {
	mount, secretPath, err := CleanKV2SecretPath("/secret/", "/airlock/openai/code-agent/")
	if err != nil {
		t.Fatal(err)
	}
	if mount != "secret" || secretPath != "airlock/openai/code-agent" {
		t.Fatalf("mount=%q path=%q, want cleaned mount and path", mount, secretPath)
	}
}

func TestCleanKV2SecretPathRejectsUnsafePaths(t *testing.T) {
	for _, secretPath := range []string{
		"../../sys/raw/secret",
		"auth/foo",
		"foo/../bar",
	} {
		t.Run(secretPath, func(t *testing.T) {
			_, _, err := CleanKV2SecretPath("secret", secretPath)
			if err == nil {
				t.Fatal("CleanKV2SecretPath() error = nil, want unsafe path error")
			}
			if !strings.Contains(err.Error(), "unsafe Vault secret path") {
				t.Fatalf("error = %q, want unsafe path", err)
			}
		})
	}
}
