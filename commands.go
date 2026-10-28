package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/term"

	"github.com/moexx399/vaultctx/internal/shell"
	"github.com/moexx399/vaultctx/internal/store"
)

func (a *app) list(ctx context.Context) error {
	cfg, err := a.st.LoadConfig()
	if err != nil {
		return err
	}
	st, err := a.st.LoadState()
	if err != nil {
		return err
	}
	if len(cfg.Contexts) == 0 {
		fmt.Fprintf(a.errw, "No contexts in %s; add one with 'vaultctx add NAME --address URL'.\n", a.st.ConfigPath())
		return nil
	}
	active := a.active(cfg, st)
	color := isTerminal(os.Stdout) && os.Getenv("NO_COLOR") == ""
	var b strings.Builder
	for _, name := range cfg.Names() {
		if name == active && color {
			fmt.Fprintf(&b, "\033[1;32m%s\033[0m\n", name)
		} else {
			fmt.Fprintln(&b, name)
		}
	}

	if _, err := exec.LookPath("fzf"); err == nil && color && os.Getenv("VAULTCTX_IGNORE_FZF") == "" {
		cmd := exec.CommandContext(ctx, "fzf", "--ansi", "--no-multi")
		cmd.Stdin = strings.NewReader(b.String())
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil // selection cancelled
		}
		if err != nil {
			return err
		}
		return a.switchTo(ctx, strings.TrimSpace(string(out)))
	}
	_, err = io.WriteString(a.out, b.String())
	return err
}

// paramsFlag collects repeated --param key=value flags.
type paramsFlag map[string]string

func (p paramsFlag) String() string { return "" }

func (p paramsFlag) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok || k == "" {
		return fmt.Errorf("expected key=value, got %q", s)
	}
	p[k] = v
	return nil
}

func (a *app) add(args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(a.errw)
	var c store.Context
	params := paramsFlag{}
	fs.StringVar(&c.Address, "address", "", "Vault address, e.g. https://vault.example.com:8200 (required)")
	fs.StringVar(&c.Namespace, "namespace", "", "Vault Enterprise namespace")
	fs.StringVar(&c.CACert, "ca-cert", "", "path to a PEM CA certificate")
	fs.StringVar(&c.ClientCert, "client-cert", "", "path to a PEM client certificate")
	fs.StringVar(&c.ClientKey, "client-key", "", "path to a PEM client key")
	fs.BoolVar(&c.SkipVerify, "skip-verify", false, "disable TLS verification (insecure)")
	fs.StringVar(&c.Auth.Method, "method", "token", "auth method: token, userpass, ldap, okta, radius, oidc, azure, or any other\n(other methods write --param values and --role to auth/<mount>/login)")
	fs.StringVar(&c.Auth.Mount, "mount", "", "auth mount path (default: the method name)")
	fs.StringVar(&c.Auth.Role, "role", "", "role for oidc, azure, and generic methods")
	fs.StringVar(&c.Auth.Username, "username", "", "username for userpass, ldap, okta, radius (default: OS user)")
	fs.IntVar(&c.Auth.CallbackPort, "callback-port", 0, "local OIDC callback port (default 8250)")
	fs.StringVar(&c.Auth.Resource, "resource", "", "Azure token resource (default https://management.azure.com/)")
	fs.Var(params, "param", "extra login field key=value (repeatable; ${VAR} is expanded at login)")
	fs.Usage = func() {
		fmt.Fprintln(a.errw, "Usage: vaultctx add NAME --address URL [flags]")
		fs.PrintDefaults()
	}

	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		c.Name, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if c.Name == "" || fs.NArg() > 0 {
		fs.Usage()
		return errors.New("expected exactly one context name")
	}
	if len(params) > 0 {
		c.Auth.Params = params
	}
	if err := c.Validate(); err != nil {
		return err
	}

	cfg, err := a.st.LoadConfig()
	if err != nil {
		return err
	}
	if _, exists := cfg.Find(c.Name); exists {
		return fmt.Errorf("context %q already exists", c.Name)
	}
	cfg.Contexts = append(cfg.Contexts, c)
	if err := a.st.SaveConfig(cfg); err != nil {
		return err
	}
	fmt.Fprintf(a.errw, "Added context %q. Switch to it with 'vaultctx %s'.\n", c.Name, c.Name)
	return nil
}

func (a *app) env(args []string) error {
	fs := flag.NewFlagSet("env", flag.ContinueOnError)
	fs.SetOutput(a.errw)
	shellName := fs.String("shell", "", "output syntax: bash, zsh, or fish (default bash/zsh)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return errUsage
	}
	sh, err := shell.Normalize(*shellName)
	if err != nil {
		return err
	}
	cfg, err := a.st.LoadConfig()
	if err != nil {
		return err
	}
	st, err := a.st.LoadState()
	if err != nil {
		return err
	}
	// Without a name this is the last context switched to, not
	// $VAULTCTX_CONTEXT, so new shells pick up the latest switch.
	name := st.Current
	if fs.NArg() == 1 {
		name = fs.Arg(0)
	}
	var c *store.Context
	if name != "" {
		var ok bool
		if c, ok = cfg.Find(name); !ok && fs.NArg() == 1 {
			return fmt.Errorf("no context named %q", name)
		}
	}
	vars, err := a.envVars(c)
	if err != nil {
		return err
	}
	return shell.WriteEnv(a.out, sh, vars)
}

func isTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// readSecret prompts on stderr and reads a line from stdin, without echo
// when stdin is a terminal.
func readSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if isTerminal(os.Stdin) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Fprintln(os.Stderr)
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
