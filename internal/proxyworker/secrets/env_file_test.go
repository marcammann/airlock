package secrets

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnvFileSecretProviderReadsEnvAndFileValues(t *testing.T) {
	t.Setenv("AIRLOCK_ENV_FILE_TEST_TOKEN", "env-token")
	provider := NewEnvFileSecretProvider(EnvFileSecretProviderOptions{})

	envValue, err := provider.Resolve(SecretRef{Provider: "env", Env: "AIRLOCK_ENV_FILE_TEST_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	if envValue != "env-token" {
		t.Fatalf("env value = %q, want env-token", envValue)
	}

	path := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(path, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileValue, err := provider.Resolve(SecretRef{Provider: "file", File: path})
	if err != nil {
		t.Fatal(err)
	}
	if fileValue != "file-token" {
		t.Fatalf("file value = %q, want file-token", fileValue)
	}
}

func TestEnvFileRespectsRoot(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "secret.txt")
	if err := os.WriteFile(inside, []byte("inside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := NewEnvFileSecretProvider(EnvFileSecretProviderOptions{SecretFileRoot: root})

	value, err := provider.Resolve(SecretRef{Provider: "file", File: inside})
	if err != nil {
		t.Fatal(err)
	}
	if value != "inside" {
		t.Fatalf("inside value = %q, want inside", value)
	}

	_, err = provider.Resolve(SecretRef{Provider: "file", File: outside})
	if err == nil {
		t.Fatal("Resolve(outside) error = nil, want root violation")
	}
}

func TestEnvFileCachesByMtime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(path, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mtime := time.Now().Add(-time.Minute).Truncate(time.Second)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	provider := NewEnvFileSecretProvider(EnvFileSecretProviderOptions{})

	first, err := provider.Resolve(SecretRef{Provider: "file", File: path})
	if err != nil {
		t.Fatal(err)
	}
	if first != "one" {
		t.Fatalf("first = %q, want one", first)
	}
	if err := os.WriteFile(path, []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	cached, err := provider.Resolve(SecretRef{Provider: "file", File: path})
	if err != nil {
		t.Fatal(err)
	}
	if cached != "one" {
		t.Fatalf("cached = %q, want cached one while mtime is unchanged", cached)
	}

	refreshedAt := mtime.Add(2 * time.Second)
	if err := os.Chtimes(path, refreshedAt, refreshedAt); err != nil {
		t.Fatal(err)
	}
	refreshed, err := provider.Resolve(SecretRef{Provider: "file", File: path})
	if err != nil {
		t.Fatal(err)
	}
	if refreshed != "two" {
		t.Fatalf("refreshed = %q, want two after mtime changes", refreshed)
	}
}

type staticSecretProvider struct {
	value string
}

func (p staticSecretProvider) Resolve(SecretRef) (string, error) {
	return p.value, nil
}

func TestReloadableSecretProviderSwapsProvider(t *testing.T) {
	provider := NewReloadableSecretProvider(staticSecretProvider{value: "one"})
	value, err := provider.Resolve(SecretRef{Provider: "env", Env: "TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	if value != "one" {
		t.Fatalf("value = %q, want one", value)
	}

	provider.Update(staticSecretProvider{value: "two"})
	value, err = provider.Resolve(SecretRef{Provider: "env", Env: "TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	if value != "two" {
		t.Fatalf("value = %q, want two", value)
	}
}
