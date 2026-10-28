package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTokenRoundTripAndPermissions(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	now := time.Now()
	if err := s.SaveToken("prod", NewToken("hvs.x", time.Hour, now)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(s.Dir, "tokens", "prod.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %v", info.Mode().Perm())
	}
	tok, err := s.LoadToken("prod")
	if err != nil || tok.Token != "hvs.x" {
		t.Fatalf("LoadToken = %v, %v", tok, err)
	}
	if tok.Expired(now) || !tok.Expired(now.Add(2*time.Hour)) {
		t.Error("unexpected expiry")
	}
	if NewToken("root", 0, now).Expired(now.Add(1000 * time.Hour)) {
		t.Error("zero TTL token should never expire")
	}
	if err := s.RenameToken("prod", "live"); err != nil {
		t.Fatal(err)
	}
	if tok, _ := s.LoadToken("live"); tok == nil {
		t.Error("renamed token missing")
	}
}

func TestLoadConfigRejectsInvalid(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	cases := map[string]string{
		"duplicate": "contexts:\n- {name: a, address: x, auth: {method: token}}\n- {name: a, address: y, auth: {method: token}}\n",
		"reserved":  "contexts:\n- {name: login, address: x, auth: {method: token}}\n",
		"path":      "contexts:\n- {name: ../a, address: x, auth: {method: token}}\n",
		"address":   "contexts:\n- {name: a, auth: {method: token}}\n",
	}
	for name, yml := range cases {
		os.WriteFile(s.ConfigPath(), []byte(yml), 0o600)
		if _, err := s.LoadConfig(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
