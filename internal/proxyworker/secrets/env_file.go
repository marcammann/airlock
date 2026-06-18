package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// EnvFileSecretProviderOptions configures local env/file secret resolution.
type EnvFileSecretProviderOptions struct {
	SecretFileRoot string
}

// EnvFileSecretProvider resolves secrets from environment variables and files.
type EnvFileSecretProvider struct {
	SecretFileRoot string
	mu             sync.Mutex
	fileCache      map[string]envFileCacheEntry
}

type envFileCacheEntry struct {
	ModTime time.Time
	Value   string
}

// NewEnvFileSecretProvider creates a provider for local env/file secrets.
func NewEnvFileSecretProvider(opts EnvFileSecretProviderOptions) *EnvFileSecretProvider {
	return &EnvFileSecretProvider{SecretFileRoot: strings.TrimSpace(opts.SecretFileRoot), fileCache: map[string]envFileCacheEntry{}}
}

// Resolve returns the secret value for an env or file secret reference.
func (p *EnvFileSecretProvider) Resolve(ref SecretRef) (string, error) {
	provider := ref.Provider
	switch ref.Provider {
	case "env":
		value, ok := os.LookupEnv(ref.Env)
		if !ok {
			err := fmt.Errorf("environment secret %q is not set", ref.Env)
			observeSecretResolve(provider, err)
			return "", err
		}
		observeSecretResolve(provider, nil)
		return value, nil
	case "file":
		value, err := p.resolveFile(ref.File)
		observeSecretResolve(provider, err)
		return value, err
	default:
		err := fmt.Errorf("secret provider %q is not available in local mode", ref.Provider)
		observeSecretResolve(provider, err)
		return "", err
	}
}

func (p *EnvFileSecretProvider) resolveFile(path string) (string, error) {
	path, err := p.resolveFilePath(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("secret file %q is a directory", path)
	}

	p.mu.Lock()
	if p.fileCache == nil {
		p.fileCache = map[string]envFileCacheEntry{}
	}
	if cached, ok := p.fileCache[path]; ok && cached.ModTime.Equal(info.ModTime()) {
		p.mu.Unlock()
		return cached.Value, nil
	}
	p.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimRight(string(data), "\r\n")

	p.mu.Lock()
	p.fileCache[path] = envFileCacheEntry{ModTime: info.ModTime(), Value: value}
	p.mu.Unlock()
	return value, nil
}

func (p *EnvFileSecretProvider) resolveFilePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("secret file path is required")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	root := strings.TrimSpace(p.SecretFileRoot)
	if root == "" {
		return absPath, nil
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return "", fmt.Errorf("resolve secret file root: %w", err)
	}
	resolvedPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(resolvedRoot, resolvedPath)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("secret file %q is outside secret file root %q", path, root)
	}
	return resolvedPath, nil
}
