# Contributing to kilhook

Thanks for helping. kilhook is a local-first Windows API workbench: one `.kh`
request file flows through send → contract validation → fuzzing → baseline diff
→ one report. The engine is plain Go; the desktop window is Wails v3 + Svelte 5.

kilhook is maintained by **24Bit System** (Two Four Bit Systech India Private
Limited). See [AUTHORS.md](AUTHORS.md); reach the team at
info@24bitsystem.com.

## Prerequisites

- **Go 1.26.9+** with toolchain go1.26.11 (see `go.mod`). With the default
  `GOTOOLCHAIN=auto`, older Go downloads it automatically; use `GOTOOLCHAIN=local`
  for offline builds.
- **Node 20+** and npm.
- **PowerShell 7** (`pwsh`) for the verification gate. The gate also expects
  `golangci-lint` and `govulncheck` on `PATH`; missing tools are reported by name
  rather than silently skipped.
- **Wails v3 CLI** and the Windows SDK if you build the desktop app or MSIX.
  Linux/macOS can run the engine tests, but `cmd/kh-app` needs GTK3/WebKitGTK
  development headers.

## Clean checkout

```powershell
npm ci --prefix cmd/kh-app/frontend
npm run build --prefix cmd/kh-app/frontend
go build -o bin/kh-cli.exe ./cmd/kh-cli
```

`npm ci` (not `npm install`) keeps the lockfile authoritative. The patched
`deepmerge` under `cmd/kh-app/frontend/vendor/` is installed via `file:` with
`.npmrc` setting `install-links=true`; see its `PATCH.md` before changing it.

`cmd/kh-app/frontend/dist/` and `cmd/kh-app/wails_windows_amd64.syso` are
committed because `cmd/kh-app` embeds them at compile time. If you touch any
frontend input, run `npm run build` again: it refreshes `dist/.source-hash`,
which the verify gate checks. Timestamp-based staleness checks do not work on a
fresh clone because git does not preserve mtimes.

## The gate

There is no CI service. The only gate is local:

```powershell
pwsh -File scripts/verify.ps1
pwsh -File scripts/verify.ps1 -Fast   # vet + race tests only
```

It runs vet, `go test -race`, golangci-lint, a `go mod tidy` check, govulncheck,
the "internal/* must not import Wails" rule, an 80% coverage floor on the six
engine packages, the frontend content-hash check, `svelte-check` and Vitest.
Exits non-zero on the first failure. Run it before opening a pull request.

`scripts/smoke.ps1` is the only networked check — it exercises the full loop
against public read-only APIs. Run it before proposing a release.

## Code conventions

- `internal/*` is pure Go: no Wails imports, no UI, no globals. Both binaries
  call `internal/engine`; do not duplicate loop logic in `cmd/`.
- A `.kh` file with untrusted input must fail safe: bound every read (file,
  spec, response, wordlist, baseline), warn instead of aborting on recoverable
  problems, and never write a path supplied by a shared file outside the
  workspace. `engine.WithinDir` is the shared confinement helper.
- Reports must not leak credentials. Extend the redaction in
  `internal/engine/redact.go` when you add a new report field.
- Fuzz payloads are non-destructive by design; `TestBundledWordlistIsNonDestructive`
  enforces it. Do not add destructive statements to the bundled wordlists.
- `format: 1` is frozen. Additive optional fields are fine; breaking changes
  need `format: 2` and a migration.
- Add a regression test with the fix. Tests use `httptest`, never public APIs.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Changes and releases

`project.md` is the design record and holds the full changelog; add an entry
there for user-visible changes. Keep version strings in sync across
`internal/report/model.go`, `cmd/kh-app/build/config.yml`,
`cmd/kh-app/build/windows/info.json` and the MSIX manifests.
