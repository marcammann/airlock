package proxyworker_test

import "testing"

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
