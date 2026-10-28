// Package login authenticates to Vault using a context's configured auth method.
package login

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"

	"github.com/hashicorp/vault/api"

	"github.com/moexx399/vaultctx/internal/store"
)

// UI is how a login interacts with the user.
type UI struct {
	// Err receives prompts and progress messages.
	Err io.Writer
	// ReadSecret prompts for a value without echoing it.
	ReadSecret func(prompt string) (string, error)
	// OpenBrowser opens a URL for browser-based logins.
	OpenBrowser func(url string) error
}

// Login authenticates client with the auth settings and returns the resulting
// token secret. The client must already have its address, namespace and TLS
// configured.
func Login(ctx context.Context, client *api.Client, a store.Auth, ui UI) (*api.Secret, error) {
	mount := a.MountPath()
	data := map[string]any{}
	for k, v := range a.Params {
		data[k] = os.ExpandEnv(v)
	}

	var (
		secret *api.Secret
		err    error
	)
	switch a.Method {
	case "token":
		secret, err = tokenLogin(ctx, client, data, ui)
	case "userpass", "ldap", "okta", "radius":
		secret, err = passwordLogin(ctx, client, mount, a.Username, data, ui)
	case "oidc":
		secret, err = oidcLogin(ctx, client, mount, a.Role, a.CallbackPort, data, ui)
	case "azure":
		secret, err = azureLogin(ctx, client, mount, a.Role, a.Resource, data)
	default:
		if a.Role != "" {
			data["role"] = a.Role
		}
		secret, err = client.Logical().WriteWithContext(ctx, "auth/"+mount+"/login", data)
	}
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, errors.New("vault returned an empty login response")
	}
	if secret.Auth != nil && secret.Auth.MFARequirement != nil {
		return nil, errors.New("login MFA is required by this auth method, which vaultctx does not support")
	}
	if id, _ := secret.TokenID(); id == "" {
		return nil, errors.New("vault login response contained no token")
	}
	return secret, nil
}

func tokenLogin(ctx context.Context, client *api.Client, data map[string]any, ui UI) (*api.Secret, error) {
	tok, _ := data["token"].(string)
	if tok == "" {
		var err error
		if tok, err = ui.ReadSecret("Token: "); err != nil {
			return nil, err
		}
	}
	client.SetToken(tok)
	return client.Auth().Token().LookupSelfWithContext(ctx)
}

func passwordLogin(ctx context.Context, client *api.Client, mount, username string, data map[string]any, ui UI) (*api.Secret, error) {
	if username == "" {
		u, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("no username configured: %w", err)
		}
		username = u.Username
	}
	if pw, _ := data["password"].(string); pw == "" {
		pw, err := ui.ReadSecret(fmt.Sprintf("Password (%s): ", username))
		if err != nil {
			return nil, err
		}
		data["password"] = pw
	}
	return client.Logical().WriteWithContext(ctx, "auth/"+mount+"/login/"+username, data)
}
