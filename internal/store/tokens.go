package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Token is a cached Vault token for one context.
type Token struct {
	Token string `json:"token"`
	// ExpiresAt is zero for tokens that never expire.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// Expired reports whether the token has expired at now.
func (t *Token) Expired(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt)
}

// NewToken builds a Token from an id and a TTL (0 means no expiry).
func NewToken(id string, ttl time.Duration, now time.Time) *Token {
	t := &Token{Token: id}
	if ttl > 0 {
		t.ExpiresAt = now.Add(ttl).UTC()
	}
	return t
}

func (s *Store) tokenPath(name string) string {
	return filepath.Join(s.Dir, "tokens", name+".json")
}

// LoadToken returns the cached token for a context, or nil if none.
func (s *Store) LoadToken(name string) (*Token, error) {
	data, err := os.ReadFile(s.tokenPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// SaveToken caches a token for a context with owner-only permissions.
func (s *Store) SaveToken(name string, t *Token) error {
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.tokenPath(name), data)
}

// DeleteToken removes a context's cached token, if any.
func (s *Store) DeleteToken(name string) error {
	err := os.Remove(s.tokenPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// RenameToken moves a cached token to a new context name, if one exists.
func (s *Store) RenameToken(from, to string) error {
	err := os.Rename(s.tokenPath(from), s.tokenPath(to))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
