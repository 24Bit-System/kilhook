# Contributing

kilhook is two binaries over one Go package. `internal/engine` does the work;
`cmd/kh-cli` and `cmd/kh-app` are thin callers. The desktop window is Wails v3
with a Svelte 5 frontend under `cmd/kh-app/frontend`.

Maintained by 24Bit System (Two Four Bit Systech India Private Limited).
Contact: info@24bitsystem.com.

## Before you start

- Go 1.26.9 or newer, with go1.26.11 available. Go 1.21+ understands the patch
  version in `go.mod` and downloads that toolchain with `GOTOOLCHAIN=auto`. Set
  `GOTOOLCHAIN=local` if you need an offline build.
- Node 20+ and npm.
- PowerShell 7 for `scripts/verify.ps1`, plus `golangci-lint` and `govulncheck`
  on PATH. The script names any tool it cannot find.
- Wails v3 and the Windows SDK for the desktop app and MSIX. On Linux and macOS
  you can run the Go engine tests and the CLI tests; `cmd/kh-app` needs GTK3 and
  WebKitGTK headers.

## Build from a checkout

```powershell
npm ci --prefix cmd/kh-app/frontend
npm run build --prefix cmd/kh-app/frontend
go build -o bin/kh-cli.exe ./cmd/kh-cli
```

Use `npm ci`, not `npm install`: the lockfile is the authority. The `deepmerge`
override points at `file:vendor/deepmerge`, and `.npmrc` sets
`install-links=true`. Do not change that patch without reading its `PATCH.md`.

`cmd/kh-app/frontend/dist/` and `cmd/kh-app/wails_windows_amd64.syso` are in git
because `cmd/kh-app` embeds them at compile time. After editing any frontend
input, run `npm run build` again. The build writes `dist/.source-hash`, which is
what `verify.ps1` checks. File timestamps do not work for this: git does not
preserve them on checkout.

## The gate

There is no CI runner. Run this before asking for a review:

```powershell
pwsh -File scripts/verify.ps1
pwsh -File scripts/verify.ps1 -Fast   # vet and race tests only
```

It runs vet, `go test -race`, golangci-lint, a tidy check on go.mod/go.sum,
govulncheck, a check that nothing under `internal/` imports Wails, an 80%
coverage floor on the six engine packages, the frontend hash check,
svelte-check and Vitest. It stops at the first failure.

`scripts/smoke.ps1` is the only networked check and the only one that touches
real APIs. Run it when you change the HTTP, fuzz, spec or diff paths.

## Review rules

- Keep `internal/*` free of Wails imports, UI code and package-level mutable
  state. Both binaries call `internal/engine`; do not reimplement the loop in
  `cmd/`.
- Treat everything read from a `.kh` file as untrusted. Bound reads, warn
  instead of failing when a target or spec is unusable, and use
  `engine.WithinDir` for any path a shared file can influence.
- Anything that reaches a report goes through `internal/engine/redact.go`. Add
  new report fields there, not later at the render layer.
- Bundled fuzz payloads stay non-destructive. `TestBundledWordlistIsNonDestructive`
  enforces it.
- `format: 1` is frozen. Optional keys can be added; breaking changes need
  `format: 2` and a migration.
- Tests use `httptest`, never a public API. Add one with your fix.

## Security

Private reports only; see [SECURITY.md](SECURITY.md).

## Changelog

Add a line to `CHANGELOG.md` for anything a user would notice. Keep the version
in `internal/report/model.go`, `cmd/kh-app/build/config.yml`,
`cmd/kh-app/build/windows/info.json` and the MSIX manifests in step.
