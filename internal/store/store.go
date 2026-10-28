// Package store persists vaultctx contexts, the current/previous selection,
// and cached Vault tokens under a single directory.
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Reserved names cannot be used for contexts because they are subcommands.
var Reserved = []string{"add", "login", "logout", "status", "env", "shell-init", "version", "help"}

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Config is the user-editable list of contexts (config.yaml).
type Config struct {
	Contexts []Context `yaml:"contexts"`
}

// Context describes one Vault server and how to log in to it.
type Context struct {
	Name       string `yaml:"name"`
	Address    string `yaml:"address"`
	Namespace  string `yaml:"namespace,omitempty"`
	CACert     string `yaml:"ca_cert,omitempty"`
	ClientCert string `yaml:"client_cert,omitempty"`
	ClientKey  string `yaml:"client_key,omitempty"`
	SkipVerify bool   `yaml:"skip_verify,omitempty"`
	Auth       Auth   `yaml:"auth"`
}

// Auth selects the auth method used by `vaultctx login`.
type Auth struct {
	// Method is the auth method type: token, userpass, ldap, okta, radius,
	// oidc, azure, or any other type, which is logged in to generically by
	// writing Params (plus role) to auth/<mount>/login.
	Method string `yaml:"method"`
	// Mount is the auth mount path; defaults to Method.
	Mount    string `yaml:"mount,omitempty"`
	Role     string `yaml:"role,omitempty"`
	Username string `yaml:"username,omitempty"`
	// Params are extra login fields sent to Vault. Values undergo
	// environment variable expansion, e.g. secret_id: ${APPROLE_SECRET_ID}.
	Params map[string]string `yaml:"params,omitempty"`
	// CallbackPort is the local OIDC callback port (default 8250).
	CallbackPort int `yaml:"callback_port,omitempty"`
	// Resource is the Azure resource to request a token for
	// (default https://management.azure.com/).
	Resource string `yaml:"resource,omitempty"`
}

// MountPath returns the auth mount path, defaulting to the method name.
func (a Auth) MountPath() string {
	if a.Mount != "" {
		return strings.Trim(a.Mount, "/")
	}
	return a.Method
}

// ValidateName reports whether name can be used as a context name.
func ValidateName(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("invalid context name %q: use letters, digits, '.', '_' or '-'", name)
	}
	if slices.Contains(Reserved, name) {
		return fmt.Errorf("invalid context name %q: reserved for a subcommand", name)
	}
	return nil
}

// Validate checks a context for required fields.
func (c Context) Validate() error {
	if err := ValidateName(c.Name); err != nil {
		return err
	}
	if c.Address == "" {
		return fmt.Errorf("context %q: address is required", c.Name)
	}
	if c.Auth.Method == "" {
		return fmt.Errorf("context %q: auth.method is required", c.Name)
	}
	return nil
}

// Find returns the context with the given name.
func (c *Config) Find(name string) (*Context, bool) {
	for i := range c.Contexts {
		if c.Contexts[i].Name == name {
			return &c.Contexts[i], true
		}
	}
	return nil, false
}

// Names returns context names in config order.
func (c *Config) Names() []string {
	names := make([]string, len(c.Contexts))
	for i, ctx := range c.Contexts {
		names[i] = ctx.Name
	}
	return names
}

// State records the current and previous context (state.yaml).
type State struct {
	Current  string `yaml:"current,omitempty"`
	Previous string `yaml:"previous,omitempty"`
}

// Store is the vaultctx home directory.
type Store struct {
	Dir string
}

// Default returns the store at $VAULTCTX_HOME, $XDG_CONFIG_HOME/vaultctx,
// or ~/.config/vaultctx.
func Default() (*Store, error) {
	if dir := os.Getenv("VAULTCTX_HOME"); dir != "" {
		return &Store{Dir: dir}, nil
	}
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return &Store{Dir: filepath.Join(dir, "vaultctx")}, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return &Store{Dir: filepath.Join(home, ".config", "vaultctx")}, nil
}

// ConfigPath is the path of config.yaml.
func (s *Store) ConfigPath() string { return filepath.Join(s.Dir, "config.yaml") }

func (s *Store) statePath() string { return filepath.Join(s.Dir, "state.yaml") }

// LoadConfig reads config.yaml; a missing file yields an empty config.
func (s *Store) LoadConfig() (*Config, error) {
	var cfg Config
	if err := readYAML(s.ConfigPath(), &cfg); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, c := range cfg.Contexts {
		if err := c.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", s.ConfigPath(), err)
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("%s: duplicate context %q", s.ConfigPath(), c.Name)
		}
		seen[c.Name] = true
	}
	return &cfg, nil
}

// SaveConfig writes config.yaml.
func (s *Store) SaveConfig(cfg *Config) error { return s.writeYAML(s.ConfigPath(), cfg) }

// LoadState reads state.yaml; a missing file yields an empty state.
func (s *Store) LoadState() (*State, error) {
	var st State
	if err := readYAML(s.statePath(), &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// SaveState writes state.yaml.
func (s *Store) SaveState(st *State) error { return s.writeYAML(s.statePath(), st) }

func readYAML(path string, v any) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func (s *Store) writeYAML(path string, v any) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

// writeFileAtomic writes data to path with 0600 permissions via a rename so
// concurrent readers never observe a partial file.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
