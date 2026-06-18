package controlplane

import (
	"fmt"
	"io"
	"os"
	"strings"
)

func resolveSecretValue(value string, path string) (string, error) {
	value = strings.TrimSpace(value)
	path = strings.TrimSpace(path)
	if value != "" {
		return value, nil
	}
	if path == "" {
		return "", fmt.Errorf("vault admin token is required when Vault reconciliation is enabled")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open Vault admin token file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read Vault admin token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("vault admin token file is empty")
	}
	return token, nil
}
