# vaultctx

`vaultctx` switches between HashiCorp Vault servers the way
[kubectx](https://github.com/ahmetb/kubectx) switches Kubernetes clusters.
Each context remembers its address, namespace, TLS settings and auth method;
`vaultctx` logs in for you and caches the token per context, so switching back
and forth does not require logging in again until a token expires.

```console
$ vaultctx
dev
prod
$ vaultctx prod
Logging in to "prod" (https://vault.example.com) with oidc...
Complete the login in your browser.
Switched to context "prod".
$ vault kv get secret/app        # uses prod's address and token
$ vaultctx -                     # back to dev, cached token reused
Switched to context "dev".
```

## Install

```bash
brew tap moexx399/tap
brew trust --cask moexx399/tap/vaultctx   # Homebrew 6+ requires trusting non-official taps
brew install --cask vaultctx
```

Or with Go: `go install github.com/moexx399/vaultctx@latest`, or download a
binary from the [releases page](https://github.com/moexx399/vaultctx/releases).

## Shell integration

Vault clients (the `vault` CLI, Terraform, SDKs) read `VAULT_ADDR`,
`VAULT_TOKEN`, `VAULT_NAMESPACE` and friends from the environment, which a
program cannot change in its parent shell. Add this to your shell rc file so
`vaultctx` updates the environment of the shell you run it in:

```bash
eval "$(vaultctx shell-init zsh)"      # ~/.zshrc
eval "$(vaultctx shell-init bash)"     # ~/.bashrc
vaultctx shell-init fish | source      # ~/.config/fish/config.fish
```

Without it, apply a context manually with `eval "$(vaultctx env)"`.

Each shell keeps its own active context (`$VAULTCTX_CONTEXT`, handy in your
prompt). New shells start in the context you most recently switched to.

## Usage

```text
vaultctx                    list contexts (interactive picker if fzf is installed)
vaultctx NAME               switch to NAME, logging in if it has no valid token
vaultctx -                  switch to the previous context
vaultctx -c, --current      print the current context
vaultctx -d NAME...         delete contexts ('.' for the current one)
vaultctx NEW=OLD            rename OLD to NEW ('.' for the current one)
vaultctx add NAME --address URL [--method M] [flags]
vaultctx login [NAME]       log in again and cache the new token
vaultctx logout [NAME]      revoke and forget the cached token
vaultctx status [NAME]      show a context and its token
vaultctx env [NAME] [--shell bash|zsh|fish]
vaultctx shell-init SHELL
```

Set `VAULTCTX_IGNORE_FZF=1` to disable the fzf picker.

## Configuration

Contexts live in `~/.config/vaultctx/config.yaml` (or
`$XDG_CONFIG_HOME/vaultctx`, or `$VAULTCTX_HOME`). Add them with
`vaultctx add` or edit the file directly:

```yaml
contexts:
  - name: prod
    address: https://vault.example.com
    namespace: admin/team-a          # Vault Enterprise / HCP
    ca_cert: /etc/ssl/vault-ca.pem   # also: client_cert, client_key, skip_verify
    auth:
      method: oidc
      role: engineer
      # mount: oidc                  # defaults to the method name
      # callback_port: 8250          # must match the role's allowed_redirect_uris
  - name: corp
    address: https://vault.corp.example.com
    auth:
      method: ldap
      username: jdoe                 # defaults to your OS user; password is prompted
  - name: azure-vm
    address: https://vault.example.com
    auth:
      method: azure
      role: app
  - name: ci
    address: https://vault.example.com
    auth:
      method: approle
      params:
        role_id: 0d6f...
        secret_id: ${APPROLE_SECRET_ID}   # ${VAR} is expanded at login
```

### Auth methods

| method | how vaultctx logs in |
| --- | --- |
| `token` | prompts for a token (or `params.token`) and verifies it |
| `userpass`, `ldap`, `okta`, `radius` | `username` + prompted password (or `params.password`); extra `params` such as `passcode` or `totp` are sent too |
| `oidc` | opens the browser, like `vault login -method=oidc`, with a local callback on `localhost:8250/oidc/callback` |
| `azure` | gets a token from the VM's managed identity, falling back to the Azure CLI (`az login`); `params` can set `subscription_id`, `resource_group_name`, `vm_name`, `vmss_name`, or `jwt`; `resource` changes the token audience |
| anything else (`approle`, `jwt`, `kubernetes`, `github`, `cert`, ...) | writes `params` (plus `role`) to `auth/<mount>/login` |

Login MFA (Vault 1.10+ `mfa_requirement`) is not supported yet.

### Token cache

Tokens are cached in `~/.config/vaultctx/tokens/<context>.json` with
owner-only (0600) permissions, alongside the token's expiry. On switch,
`vaultctx` verifies a cached token with Vault and logs in again if it has
expired or been revoked; if Vault is unreachable it keeps the cached token.
`vaultctx logout` revokes the token and removes it from the cache.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every change needs a
[changie](https://changie.dev) entry.

## License

[Apache License 2.0](LICENSE).
