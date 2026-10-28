# vaultctx

kubectx-style context switcher for HashiCorp Vault, written in Go.

- Every user-visible change must add a changie fragment (`changie new --kind <Added|Changed|Deprecated|Removed|Fixed|Security> --body "..."`). Never edit `CHANGELOG.md` directly.
- Run `go test -race ./...` and `go vet ./...` before committing.
- Layout: `main.go`/`commands.go` (CLI), `internal/store` (config, state, token cache), `internal/login` (auth methods), `internal/shell` (env exports and shell-init).
- Releases: see CONTRIBUTING.md (changie batch/merge, tag, GoReleaser publishes the Homebrew cask).
