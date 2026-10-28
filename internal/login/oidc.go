package login

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"sync"

	"github.com/hashicorp/vault/api"
)

const defaultOIDCPort = 8250

type callbackResult struct {
	secret *api.Secret
	err    error
}

// oidcLogin performs the same browser flow as `vault login -method=oidc`:
// request an auth URL, open it, and exchange the redirect on a local
// callback listener for a Vault token.
func oidcLogin(ctx context.Context, client *api.Client, mount, role string, port int, data map[string]any, ui UI) (*api.Secret, error) {
	if port == 0 {
		port = defaultOIDCPort
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return nil, fmt.Errorf("start OIDC callback listener: %w", err)
	}
	defer ln.Close()

	nonceBytes := make([]byte, 20)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(nonceBytes)

	data["role"] = role
	data["redirect_uri"] = fmt.Sprintf("http://localhost:%d/oidc/callback", port)
	data["client_nonce"] = nonce
	secret, err := client.Logical().WriteWithContext(ctx, "auth/"+mount+"/oidc/auth_url", data)
	if err != nil {
		return nil, fmt.Errorf("request OIDC auth URL: %w", err)
	}
	var authURL string
	if secret != nil {
		authURL, _ = secret.Data["auth_url"].(string)
	}
	if authURL == "" {
		return nil, fmt.Errorf("vault returned no OIDC auth URL; check that %s is an allowed_redirect_uri for role %q", data["redirect_uri"], role)
	}

	results := make(chan callbackResult, 1)
	var once sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		// Providers using response_mode=form_post POST the parameters.
		_ = r.ParseForm()
		var res callbackResult
		if e := r.Form.Get("error"); e != "" {
			res.err = fmt.Errorf("OIDC provider error: %s %s", e, r.Form.Get("error_description"))
		} else {
			q := map[string][]string{
				"state":        {r.Form.Get("state")},
				"code":         {r.Form.Get("code")},
				"id_token":     {r.Form.Get("id_token")},
				"client_nonce": {nonce},
			}
			res.secret, res.err = client.Logical().ReadWithDataWithContext(ctx, "auth/"+mount+"/oidc/callback", q)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if res.err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "<html><body><h2>Vault login failed</h2><pre>%s</pre></body></html>", html.EscapeString(res.err.Error()))
		} else {
			fmt.Fprint(w, "<html><body><h2>Vault login succeeded</h2><p>You can close this window.</p></body></html>")
		}
		once.Do(func() { results <- res })
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	fmt.Fprintf(ui.Err, "Complete the login in your browser. If it did not open, visit:\n\n    %s\n\n", authURL)
	if err := ui.OpenBrowser(authURL); err != nil {
		fmt.Fprintf(ui.Err, "warning: could not open browser: %v\n", err)
	}

	select {
	case res := <-results:
		return res.secret, res.err
	case <-ctx.Done():
		return nil, errors.New("OIDC login cancelled")
	}
}
