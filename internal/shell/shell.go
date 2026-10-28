// Package shell renders environment exports and shell integration scripts.
package shell

import (
	"fmt"
	"io"
	"strings"
)

// Vars lists every variable vaultctx manages, in output order. Variables a
// context does not set are unset so nothing leaks between contexts.
var Vars = []string{
	"VAULTCTX_CONTEXT",
	"VAULT_ADDR",
	"VAULT_TOKEN",
	"VAULT_NAMESPACE",
	"VAULT_CACERT",
	"VAULT_CLIENT_CERT",
	"VAULT_CLIENT_KEY",
	"VAULT_SKIP_VERIFY",
}

// Supported shells for env output and shell-init.
const (
	POSIX = "sh"
	Fish  = "fish"
)

// WriteEnv writes statements that set vars (and unset the rest of Vars) in
// the given shell syntax.
func WriteEnv(w io.Writer, sh string, vars map[string]string) error {
	for _, k := range Vars {
		v, ok := vars[k]
		var err error
		switch {
		case sh == Fish && ok && v != "":
			_, err = fmt.Fprintf(w, "set -gx %s %s;\n", k, fishQuote(v))
		case sh == Fish:
			_, err = fmt.Fprintf(w, "set -e %s;\n", k)
		case ok && v != "":
			_, err = fmt.Fprintf(w, "export %s=%s;\n", k, posixQuote(v))
		default:
			_, err = fmt.Fprintf(w, "unset %s;\n", k)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func posixQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func fishQuote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// Normalize maps a shell name to the env syntax it uses.
func Normalize(name string) (string, error) {
	switch name {
	case "", "sh", "bash", "zsh":
		return POSIX, nil
	case "fish":
		return Fish, nil
	}
	return "", fmt.Errorf("unsupported shell %q (supported: bash, zsh, fish)", name)
}

// Init returns the shell-init script for a shell. It wraps the binary in a
// function so commands that change the active context also update the
// calling shell's environment, then loads the current context's environment.
func Init(name string) (string, error) {
	sh, err := Normalize(name)
	if err != nil {
		return "", err
	}
	if sh == Fish {
		return fishInit, nil
	}
	return posixInit, nil
}

const posixInit = `vaultctx() {
  local __vaultctx_env __vaultctx_rc
  __vaultctx_env="$(mktemp "${TMPDIR:-/tmp}/vaultctx.XXXXXX")" || return
  VAULTCTX_ENV_FILE="$__vaultctx_env" VAULTCTX_SHELL=sh command vaultctx "$@"
  __vaultctx_rc=$?
  if [ -s "$__vaultctx_env" ]; then . "$__vaultctx_env"; fi
  rm -f "$__vaultctx_env"
  return $__vaultctx_rc
}
eval "$(command vaultctx env)"
`

const fishInit = `function vaultctx
  set -l __vaultctx_env (mktemp)
  or return
  env VAULTCTX_ENV_FILE=$__vaultctx_env VAULTCTX_SHELL=fish vaultctx $argv
  set -l __vaultctx_rc $status
  test -s $__vaultctx_env; and source $__vaultctx_env
  rm -f $__vaultctx_env
  return $__vaultctx_rc
end
command vaultctx env --shell fish | source
`
