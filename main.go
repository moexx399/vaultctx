// Command vaultctx switches between HashiCorp Vault contexts, kubectx-style,
// logging in with each context's auth method and caching its token.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/moexx399/vaultctx/internal/login"
	"github.com/moexx399/vaultctx/internal/shell"
	"github.com/moexx399/vaultctx/internal/store"
)

// version is set at build time by GoReleaser.
var version = "dev"

const usage = `vaultctx switches between HashiCorp Vault contexts.

USAGE:
  vaultctx                    list contexts (interactive picker if fzf is installed)
  vaultctx NAME               switch to NAME, logging in if it has no valid token
  vaultctx -                  switch to the previous context
  vaultctx -c, --current      print the current context
  vaultctx -d NAME...         delete contexts ('.' for the current one)
  vaultctx NEW=OLD            rename OLD to NEW ('.' for the current one)

  vaultctx add NAME --address URL [--method M] [flags]   add a context
  vaultctx login [NAME]       log in again and cache the new token
  vaultctx logout [NAME]      revoke and forget the cached token
  vaultctx status [NAME]      show a context and its token
  vaultctx env [NAME] [--shell bash|zsh|fish]
                              print exports for VAULT_ADDR, VAULT_TOKEN, ...
  vaultctx shell-init SHELL   print shell integration (bash, zsh, fish)
  vaultctx version            print the version

Commands default to the active context: $VAULTCTX_CONTEXT if set, otherwise
the last context switched to. Run 'vaultctx add -h' for auth method flags.

Shell integration (add to your shell rc file) keeps the environment in sync:
  eval "$(vaultctx shell-init zsh)"
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, os.Args[1:])
	stop()
	if errors.Is(err, errUsage) {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

func run(ctx context.Context, args []string) error {
	st, err := store.Default()
	if err != nil {
		return err
	}
	a := &app{
		st:   st,
		out:  os.Stdout,
		errw: os.Stderr,
		now:  time.Now,
		ui: login.UI{
			Err:         os.Stderr,
			ReadSecret:  readSecret,
			OpenBrowser: openBrowser,
		},
	}
	return a.run(ctx, args)
}

type app struct {
	st   *store.Store
	out  io.Writer
	errw io.Writer
	now  func() time.Time
	ui   login.UI
}

func (a *app) run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return a.list(ctx)
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Fprint(a.out, usage)
		return nil
	case "version", "-v", "--version":
		fmt.Fprintln(a.out, version)
		return nil
	case "-c", "--current":
		return a.current()
	case "-d", "--delete":
		return a.delete(rest)
	case "add":
		return a.add(rest)
	case "login":
		return a.withOptionalName(rest, func(name string) error { return a.loginCmd(ctx, name) })
	case "logout":
		return a.withOptionalName(rest, func(name string) error { return a.logout(ctx, name) })
	case "status":
		return a.withOptionalName(rest, func(name string) error { return a.status(ctx, name) })
	case "env":
		return a.env(rest)
	case "shell-init":
		if len(rest) != 1 {
			return errUsage
		}
		script, err := shell.Init(rest[0])
		if err != nil {
			return err
		}
		fmt.Fprint(a.out, script)
		return nil
	}
	if len(rest) > 0 {
		return errUsage
	}
	switch {
	case cmd == "-":
		return a.switchPrevious(ctx)
	case strings.Contains(cmd, "="):
		newName, oldName, _ := strings.Cut(cmd, "=")
		return a.rename(oldName, newName)
	case strings.HasPrefix(cmd, "-"):
		return errUsage
	}
	return a.switchTo(ctx, cmd)
}

func (a *app) withOptionalName(args []string, fn func(string) error) error {
	if len(args) > 1 {
		return errUsage
	}
	if len(args) == 1 {
		return fn(args[0])
	}
	return fn("")
}

// active returns the context this shell is using: $VAULTCTX_CONTEXT when it
// names an existing context, otherwise the last one switched to.
func (a *app) active(cfg *store.Config, st *store.State) string {
	if name := os.Getenv("VAULTCTX_CONTEXT"); name != "" {
		if _, ok := cfg.Find(name); ok {
			return name
		}
	}
	return st.Current
}

// resolve loads config and state and finds the named context, where "" and
// "." mean the active context.
func (a *app) resolve(name string) (*store.Config, *store.State, *store.Context, error) {
	cfg, err := a.st.LoadConfig()
	if err != nil {
		return nil, nil, nil, err
	}
	st, err := a.st.LoadState()
	if err != nil {
		return nil, nil, nil, err
	}
	if name == "" || name == "." {
		name = a.active(cfg, st)
		if name == "" {
			return nil, nil, nil, errors.New("no current context; switch with 'vaultctx NAME'")
		}
	}
	c, ok := cfg.Find(name)
	if !ok {
		return nil, nil, nil, fmt.Errorf("no context named %q", name)
	}
	return cfg, st, c, nil
}

func (a *app) current() error {
	cfg, err := a.st.LoadConfig()
	if err != nil {
		return err
	}
	st, err := a.st.LoadState()
	if err != nil {
		return err
	}
	name := a.active(cfg, st)
	if name == "" {
		return errors.New("no current context")
	}
	fmt.Fprintln(a.out, name)
	return nil
}

func (a *app) switchTo(ctx context.Context, name string) error {
	cfg, st, c, err := a.resolve(name)
	if err != nil {
		return err
	}
	if _, err := a.ensureToken(ctx, c, false); err != nil {
		return err
	}
	if from := a.active(cfg, st); from != c.Name {
		st.Previous = from
	}
	st.Current = c.Name
	if err := a.st.SaveState(st); err != nil {
		return err
	}
	if err := a.exportEnv(c); err != nil {
		return err
	}
	fmt.Fprintf(a.errw, "Switched to context %q.\n", c.Name)
	if os.Getenv("VAULTCTX_ENV_FILE") == "" {
		fmt.Fprintln(a.errw, `hint: run 'eval "$(vaultctx env)"' to update this shell, or set up 'vaultctx shell-init'.`)
	}
	return nil
}

func (a *app) switchPrevious(ctx context.Context) error {
	st, err := a.st.LoadState()
	if err != nil {
		return err
	}
	if st.Previous == "" {
		return errors.New("no previous context")
	}
	return a.switchTo(ctx, st.Previous)
}

func (a *app) delete(names []string) error {
	if len(names) == 0 {
		return errUsage
	}
	cfg, err := a.st.LoadConfig()
	if err != nil {
		return err
	}
	st, err := a.st.LoadState()
	if err != nil {
		return err
	}
	active := a.active(cfg, st)
	deletedActive := false
	for _, name := range names {
		if name == "." {
			name = active
		}
		i := slices.IndexFunc(cfg.Contexts, func(c store.Context) bool { return c.Name == name })
		if i < 0 {
			return fmt.Errorf("no context named %q", name)
		}
		cfg.Contexts = slices.Delete(cfg.Contexts, i, i+1)
		if err := a.st.DeleteToken(name); err != nil {
			return err
		}
		if st.Current == name {
			st.Current = ""
		}
		if st.Previous == name {
			st.Previous = ""
		}
		deletedActive = deletedActive || name == active
		fmt.Fprintf(a.errw, "Deleted context %q.\n", name)
	}
	if err := a.st.SaveConfig(cfg); err != nil {
		return err
	}
	if err := a.st.SaveState(st); err != nil {
		return err
	}
	if deletedActive {
		return a.exportEnv(nil)
	}
	return nil
}

func (a *app) rename(oldName, newName string) error {
	cfg, st, c, err := a.resolve(oldName)
	if err != nil {
		return err
	}
	oldName = c.Name
	if err := store.ValidateName(newName); err != nil {
		return err
	}
	if _, exists := cfg.Find(newName); exists {
		return fmt.Errorf("context %q already exists", newName)
	}
	wasActive := a.active(cfg, st) == oldName
	c.Name = newName
	if err := a.st.SaveConfig(cfg); err != nil {
		return err
	}
	if err := a.st.RenameToken(oldName, newName); err != nil {
		return err
	}
	if st.Current == oldName {
		st.Current = newName
	}
	if st.Previous == oldName {
		st.Previous = newName
	}
	if err := a.st.SaveState(st); err != nil {
		return err
	}
	fmt.Fprintf(a.errw, "Context %q renamed to %q.\n", oldName, newName)
	if wasActive {
		return a.exportEnv(c)
	}
	return nil
}

func (a *app) loginCmd(ctx context.Context, name string) error {
	cfg, st, c, err := a.resolve(name)
	if err != nil {
		return err
	}
	tok, err := a.ensureToken(ctx, c, true)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.errw, "Logged in to %q (%s).\n", c.Name, a.describeExpiry(tok))
	if a.active(cfg, st) == c.Name {
		return a.exportEnv(c)
	}
	return nil
}

func (a *app) logout(ctx context.Context, name string) error {
	cfg, st, c, err := a.resolve(name)
	if err != nil {
		return err
	}
	tok, err := a.st.LoadToken(c.Name)
	if err != nil {
		return err
	}
	if tok != nil && !tok.Expired(a.now()) {
		client, err := newClient(c)
		if err != nil {
			return err
		}
		client.SetToken(tok.Token)
		if err := client.Auth().Token().RevokeSelfWithContext(ctx, ""); err != nil {
			fmt.Fprintf(a.errw, "warning: could not revoke token: %v\n", err)
		}
	}
	if err := a.st.DeleteToken(c.Name); err != nil {
		return err
	}
	fmt.Fprintf(a.errw, "Logged out of %q.\n", c.Name)
	if a.active(cfg, st) == c.Name {
		return a.exportEnv(c)
	}
	return nil
}

func (a *app) status(ctx context.Context, name string) error {
	_, _, c, err := a.resolve(name)
	if err != nil {
		return err
	}
	w := a.out
	fmt.Fprintf(w, "Context:    %s\n", c.Name)
	fmt.Fprintf(w, "Address:    %s\n", c.Address)
	if c.Namespace != "" {
		fmt.Fprintf(w, "Namespace:  %s\n", c.Namespace)
	}
	authDesc := fmt.Sprintf("%s (mount %s", c.Auth.Method, c.Auth.MountPath())
	if c.Auth.Role != "" {
		authDesc += ", role " + c.Auth.Role
	}
	fmt.Fprintf(w, "Auth:       %s)\n", authDesc)

	tok, err := a.st.LoadToken(c.Name)
	if err != nil {
		return err
	}
	if tok == nil || tok.Expired(a.now()) {
		fmt.Fprintln(w, "Token:      none (run 'vaultctx login')")
		return nil
	}
	client, err := newClient(c)
	if err != nil {
		return err
	}
	client.SetToken(tok.Token)
	secret, err := client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		fmt.Fprintf(w, "Token:      cached, but lookup failed: %v\n", err)
		return nil
	}
	ttl, _ := secret.TokenTTL()
	policies, _ := secret.TokenPolicies()
	displayName, _ := secret.Data["display_name"].(string)
	fmt.Fprintf(w, "Token:      valid, %s\n", a.describeExpiry(store.NewToken(tok.Token, ttl, a.now())))
	fmt.Fprintf(w, "Identity:   %s\n", displayName)
	fmt.Fprintf(w, "Policies:   %s\n", strings.Join(policies, ", "))
	return nil
}

func (a *app) describeExpiry(t *store.Token) string {
	if t.ExpiresAt.IsZero() {
		return "token does not expire"
	}
	return "token expires in " + t.ExpiresAt.Sub(a.now()).Round(time.Second).String()
}

// ensureToken returns a usable token for c, reusing the cached one unless
// force is set or Vault rejects it, and otherwise logging in and caching the
// result.
func (a *app) ensureToken(ctx context.Context, c *store.Context, force bool) (*store.Token, error) {
	client, err := newClient(c)
	if err != nil {
		return nil, err
	}
	if !force {
		tok, err := a.st.LoadToken(c.Name)
		if err != nil {
			return nil, err
		}
		if tok != nil && !tok.Expired(a.now()) {
			client.SetToken(tok.Token)
			_, err := client.Auth().Token().LookupSelfWithContext(ctx)
			var respErr *api.ResponseError
			switch {
			case err == nil:
				return tok, nil
			case errors.As(err, &respErr) && respErr.StatusCode == 403:
				fmt.Fprintf(a.errw, "Cached token for %q is no longer valid.\n", c.Name)
			default:
				// Keep working offline or when Vault is briefly unreachable.
				fmt.Fprintf(a.errw, "warning: could not verify cached token: %v\n", err)
				return tok, nil
			}
		}
		client.SetToken("")
	}

	fmt.Fprintf(a.errw, "Logging in to %q (%s) with %s...\n", c.Name, c.Address, c.Auth.Method)
	secret, err := login.Login(ctx, client, c.Auth, a.ui)
	if err != nil {
		return nil, fmt.Errorf("login to %q: %w", c.Name, err)
	}
	id, _ := secret.TokenID()
	ttl, _ := secret.TokenTTL()
	tok := store.NewToken(id, ttl, a.now())
	if err := a.st.SaveToken(c.Name, tok); err != nil {
		return nil, err
	}
	return tok, nil
}

// envVars returns the environment for c (nil c unsets everything).
func (a *app) envVars(c *store.Context) (map[string]string, error) {
	if c == nil {
		return nil, nil
	}
	vars := map[string]string{
		"VAULTCTX_CONTEXT":  c.Name,
		"VAULT_ADDR":        c.Address,
		"VAULT_NAMESPACE":   c.Namespace,
		"VAULT_CACERT":      c.CACert,
		"VAULT_CLIENT_CERT": c.ClientCert,
		"VAULT_CLIENT_KEY":  c.ClientKey,
	}
	if c.SkipVerify {
		vars["VAULT_SKIP_VERIFY"] = "true"
	}
	tok, err := a.st.LoadToken(c.Name)
	if err != nil {
		return nil, err
	}
	if tok != nil && !tok.Expired(a.now()) {
		vars["VAULT_TOKEN"] = tok.Token
	}
	return vars, nil
}

// exportEnv updates the calling shell through the shell-init wrapper, which
// passes a file to source in $VAULTCTX_ENV_FILE. Without it this is a no-op.
func (a *app) exportEnv(c *store.Context) error {
	path := os.Getenv("VAULTCTX_ENV_FILE")
	if path == "" {
		return nil
	}
	sh, err := shell.Normalize(os.Getenv("VAULTCTX_SHELL"))
	if err != nil {
		return err
	}
	vars, err := a.envVars(c)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := shell.WriteEnv(f, sh, vars); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// newClient builds a Vault client from the context alone, ignoring VAULT_*
// variables a previously active context exported into this environment.
func newClient(c *store.Context) (*api.Client, error) {
	for _, k := range []string{
		"VAULT_ADDR", "VAULT_AGENT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE",
		"VAULT_CACERT", "VAULT_CAPATH", "VAULT_CLIENT_CERT", "VAULT_CLIENT_KEY",
		"VAULT_SKIP_VERIFY", "VAULT_TLS_SERVER_NAME", "VAULT_WRAP_TTL",
	} {
		os.Unsetenv(k)
	}
	cfg := api.DefaultConfig()
	if cfg.Error != nil {
		return nil, cfg.Error
	}
	cfg.Address = c.Address
	if err := cfg.ConfigureTLS(&api.TLSConfig{
		CACert:     c.CACert,
		ClientCert: c.ClientCert,
		ClientKey:  c.ClientKey,
		Insecure:   c.SkipVerify,
	}); err != nil {
		return nil, err
	}
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	client.SetToken("")
	if c.Namespace != "" {
		client.SetNamespace(c.Namespace)
	}
	return client, nil
}
