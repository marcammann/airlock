package enrollment

import (
	"strings"
	"testing"
	"time"

	"github.com/marcammann/airlock/internal/policy"
)

func TestStoreMintRedeemConsumesToken(t *testing.T) {
	store := NewStore(StoreOptions{DefaultTTL: time.Minute})
	now := time.Now().UTC()
	compiled := policy.CompiledPolicy{PolicyName: "demo"}

	token, expiresAt, err := store.Mint(compiled, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "al_enroll_") {
		t.Fatalf("token = %q, want enrollment prefix", token)
	}
	if !expiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("expiresAt = %s, want default ttl", expiresAt)
	}

	got, gotExpiresAt, err := store.Redeem(token, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got.PolicyName != compiled.PolicyName || !gotExpiresAt.Equal(expiresAt) {
		t.Fatalf("redeemed policy=%+v expiresAt=%s, want original", got, gotExpiresAt)
	}
	if _, _, err := store.Redeem(token, now.Add(2*time.Second)); err == nil {
		t.Fatal("Redeem() second use error = nil, want consumed token")
	}
}

func TestStoreCapsTTLAndSweepsExpiredTokens(t *testing.T) {
	store := NewStore(StoreOptions{DefaultTTL: time.Hour, MaxTTL: 5 * time.Minute})
	now := time.Now().UTC()
	token, expiresAt, err := store.Mint(policy.CompiledPolicy{PolicyName: "demo"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if !expiresAt.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("expiresAt = %s, want max ttl cap", expiresAt)
	}
	if deleted := store.SweepExpired(now.Add(6 * time.Minute)); deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}
	if _, _, err := store.Redeem(token, now.Add(6*time.Minute)); err == nil {
		t.Fatal("Redeem() after sweep error = nil, want invalid token")
	}
}
