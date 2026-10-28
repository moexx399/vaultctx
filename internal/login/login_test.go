package login

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/moexx399/vaultctx/internal/store"
)

func newTestClient(t *testing.T, h http.Handler) *api.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cfg := api.DefaultConfig()
	cfg.Address = srv.URL
	cfg.MaxRetries = 0
	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken("")
	return client
}

func writeAuth(w http.ResponseWriter, token string) {
	json.NewEncoder(w).Encode(map[string]any{
		"auth": map[string]any{"client_token": token, "lease_duration": 3600},
	})
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestPasswordLoginPromptsAndExpandsParams(t *testing.T) {
	t.Setenv("TOTP", "123456")
	var got map[string]any
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/corp-ldap/login/alice" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&got)
		writeAuth(w, "tok-ldap")
	}))
	ui := UI{Err: io.Discard, ReadSecret: func(string) (string, error) { return "s3cret", nil }}
	secret, err := Login(context.Background(), client, store.Auth{
		Method: "ldap", Mount: "corp-ldap/", Username: "alice",
		Params: map[string]string{"passcode": "${TOTP}"},
	}, ui)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := secret.TokenID(); id != "tok-ldap" {
		t.Errorf("token = %q", id)
	}
	if got["password"] != "s3cret" || got["passcode"] != "123456" {
		t.Errorf("login body = %v", got)
	}
}

func TestGenericLoginSendsRole(t *testing.T) {
	var got map[string]any
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/jwt/login" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&got)
		writeAuth(w, "tok-jwt")
	}))
	_, err := Login(context.Background(), client, store.Auth{
		Method: "jwt", Role: "dev", Params: map[string]string{"jwt": "abc"},
	}, UI{Err: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if got["role"] != "dev" || got["jwt"] != "abc" {
		t.Errorf("login body = %v", got)
	}
}

func TestOIDCLogin(t *testing.T) {
	port := freePort(t)
	mux := http.NewServeMux()
	var nonce string
	mux.HandleFunc("/v1/auth/oidc/oidc/auth_url", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		nonce = body["client_nonce"]
		want := fmt.Sprintf("http://localhost:%d/oidc/callback", port)
		if body["redirect_uri"] != want || body["role"] != "eng" || nonce == "" {
			t.Errorf("auth_url body = %v", body)
		}
		// The "IdP" immediately redirects back to the callback.
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"auth_url": want + "?state=st&code=cd",
		}})
	})
	mux.HandleFunc("/v1/auth/oidc/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != "st" || q.Get("code") != "cd" || q.Get("client_nonce") != nonce {
			t.Errorf("callback query = %v", q)
		}
		writeAuth(w, "tok-oidc")
	})
	client := newTestClient(t, mux)

	browserErr := make(chan error, 1)
	ui := UI{
		Err: io.Discard,
		OpenBrowser: func(u string) error {
			go func() {
				resp, err := http.Get(u)
				if err == nil {
					resp.Body.Close()
				}
				browserErr <- err
			}()
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	secret, err := Login(ctx, client, store.Auth{Method: "oidc", Role: "eng", CallbackPort: port}, ui)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := secret.TokenID(); id != "tok-oidc" {
		t.Errorf("token = %q", id)
	}
	if ttl, _ := secret.TokenTTL(); ttl != time.Hour {
		t.Errorf("ttl = %v", ttl)
	}
	if err := <-browserErr; err != nil {
		t.Errorf("browser request: %v", err)
	}
}

func TestOIDCProviderError(t *testing.T) {
	port := freePort(t)
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"auth_url": fmt.Sprintf("http://localhost:%d/oidc/callback?", port) +
				url.Values{"error": {"access_denied"}}.Encode(),
		}})
	}))
	ui := UI{Err: io.Discard, OpenBrowser: func(u string) error {
		go func() {
			if resp, err := http.Get(u); err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}}
	_, err := Login(context.Background(), client, store.Auth{Method: "oidc", CallbackPort: port}, ui)
	if err == nil {
		t.Fatal("expected provider error")
	}
}
