// Package enrollment manages one-time proxy-worker enrollment tokens.
package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/marcammann/airlock/internal/policy"
)

const (
	defaultEnrollmentTTL = 2 * time.Minute
	defaultEnrollmentMax = 10 * time.Minute
)

// Store keeps hashed one-time enrollment tokens in memory.
type Store struct {
	mu         sync.Mutex
	tokens     map[string]record
	defaultTTL time.Duration
	maxTTL     time.Duration
}

type record struct {
	Policy    policy.CompiledPolicy
	ExpiresAt time.Time
}

// StoreOptions configures enrollment token lifetimes.
type StoreOptions struct {
	DefaultTTL time.Duration
	MaxTTL     time.Duration
}

// NewStore creates an in-memory enrollment token store.
func NewStore(opts StoreOptions) *Store {
	defaultTTL := opts.DefaultTTL
	if defaultTTL <= 0 {
		defaultTTL = defaultEnrollmentTTL
	}
	maxTTL := opts.MaxTTL
	if maxTTL <= 0 {
		maxTTL = defaultEnrollmentMax
	}
	if defaultTTL > maxTTL {
		defaultTTL = maxTTL
	}
	return &Store{
		tokens:     map[string]record{},
		defaultTTL: defaultTTL,
		maxTTL:     maxTTL,
	}
}

// Mint creates a one-time enrollment token for a compiled policy.
func (s *Store) Mint(compiled policy.CompiledPolicy, requestedTTL time.Duration, now time.Time) (string, time.Time, error) {
	if s == nil {
		return "", time.Time{}, fmt.Errorf("enrollment store is not configured")
	}
	ttl := requestedTTL
	if ttl <= 0 {
		ttl = s.defaultTTL
	}
	if ttl > s.maxTTL {
		ttl = s.maxTTL
	}
	token, err := randomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := now.Add(ttl).UTC()
	s.mu.Lock()
	s.tokens[hashToken(token)] = record{
		Policy:    compiled,
		ExpiresAt: expiresAt,
	}
	s.mu.Unlock()
	return token, expiresAt, nil
}

// Redeem consumes a one-time enrollment token and returns its policy.
func (s *Store) Redeem(token string, now time.Time) (policy.CompiledPolicy, time.Time, error) {
	if s == nil {
		return policy.CompiledPolicy{}, time.Time{}, fmt.Errorf("enrollment store is not configured")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return policy.CompiledPolicy{}, time.Time{}, fmt.Errorf("enrollment token is required")
	}
	hash := hashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.tokens[hash]
	if !ok {
		return policy.CompiledPolicy{}, time.Time{}, fmt.Errorf("enrollment token is invalid")
	}
	delete(s.tokens, hash)
	if now.After(record.ExpiresAt) {
		return policy.CompiledPolicy{}, record.ExpiresAt, fmt.Errorf("enrollment token expired")
	}
	return record.Policy, record.ExpiresAt, nil
}

// RunSweeper periodically deletes expired enrollment tokens.
func (s *Store) RunSweeper(ctx context.Context, interval time.Duration) {
	if s == nil {
		return
	}
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.SweepExpired(now.UTC())
		}
	}
}

// SweepExpired deletes expired enrollment tokens and returns the delete count.
func (s *Store) SweepExpired(now time.Time) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	deleted := 0
	for token, record := range s.tokens {
		if now.After(record.ExpiresAt) {
			delete(s.tokens, token)
			deleted++
		}
	}
	return deleted
}

// Count returns the number of currently retained enrollment tokens.
func (s *Store) Count() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens)
}

func randomToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate enrollment token: %w", err)
	}
	return "al_enroll_" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
