// Package vaultpath validates Vault KV-v2 mount and secret paths.
package vaultpath

import (
	"fmt"
	pathpkg "path"
	"strings"
)

// CleanKV2SecretPath validates and cleans a Vault KV-v2 mount and secret path.
func CleanKV2SecretPath(mount string, secretPath string) (string, string, error) {
	mount = strings.Trim(strings.TrimSpace(mount), "/")
	secretPath = strings.Trim(strings.TrimSpace(secretPath), "/")
	if mount == "" {
		return "", "", fmt.Errorf("vault mount is required")
	}
	if secretPath == "" {
		return "", "", fmt.Errorf("vault secret path is required")
	}
	cleaned := pathpkg.Clean(secretPath)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || ContainsDotDotSegment(secretPath) {
		return "", "", fmt.Errorf("unsafe Vault secret path")
	}
	if IsUnsafe(cleaned) || IsUnsafe(mount+"/"+cleaned) {
		return "", "", fmt.Errorf("unsafe Vault secret path")
	}
	return mount, cleaned, nil
}

// ContainsDotDotSegment reports whether a path contains a literal ".." segment.
func ContainsDotDotSegment(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

// IsUnsafe reports whether a path targets Vault system or auth mounts.
func IsUnsafe(value string) bool {
	clean := strings.Trim(strings.TrimSpace(value), "/")
	return clean == "sys" || clean == "auth" || strings.HasPrefix(clean, "sys/") || strings.HasPrefix(clean, "auth/")
}
