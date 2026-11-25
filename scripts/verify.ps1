# Local verification gate for kilhook.
#
# There is no CI service and no version-control host. This script is the gate:
# a change that cannot leave it green does not land. A skipped run is a failed
# run.
#
# Usage:  pwsh -File scripts/verify.ps1            (full gate)
#         pwsh -File scripts/verify.ps1 -Fast      (vet + test only)

[CmdletBinding()]
param(
    [switch]$Fast
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$script:failures = @()
$script:step = 0

function Write-Step([string]$name) {
    $script:step++
    Write-Host ""
    Write-Host ("[{0}] {1}" -f $script:step, $name) -ForegroundColor Cyan
}

function Fail([string]$message) {
    Write-Host "    FAIL: $message" -ForegroundColor Red
    $script:failures += $message
}

function Complete {
    Write-Host ""
    Write-Host "----------------------------------------"
    if ($script:failures.Count -gt 0) {
        Write-Host ("verify FAILED ({0} problem(s))" -f $script:failures.Count) -ForegroundColor Red
        foreach ($f in $script:failures) { Write-Host "  - $f" -ForegroundColor Red }
        exit 1
    }
    Write-Host "verify passed" -ForegroundColor Green
    exit 0
}

function Require-Tool([string]$tool, [string]$hint) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Fail "$tool is not installed. $hint"
        return $false
    }
    return $true
}

Write-Host "kilhook verify - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White

# 1. vet ---------------------------------------------------------------------
Write-Step "go vet ./..."
$out = & go vet ./... 2>&1
if ($LASTEXITCODE -ne 0) { Fail "go vet reported problems:`n$out" } else { Write-Host "    ok" -ForegroundColor Green }

# 2. tests with the race detector -------------------------------------------
Write-Step "go test ./... -race"
$out = & go test ./... -race -count=1 2>&1
if ($LASTEXITCODE -ne 0) { Fail "tests failed:`n$out" } else { Write-Host "    ok" -ForegroundColor Green }

if ($Fast) { Complete }

# 3. lint --------------------------------------------------------------------
Write-Step "golangci-lint run"
if (Require-Tool 'golangci-lint' 'Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest') {
    $out = & golangci-lint run 2>&1
    if ($LASTEXITCODE -ne 0) { Fail "golangci-lint reported problems:`n$out" } else { Write-Host "    ok" -ForegroundColor Green }
}

# 4. go.mod must be tidy (compares against a temp copy: there is no VCS) -----
Write-Step "go mod tidy check"
$modBackup = Join-Path $env:TEMP ("kilhook-go.mod." + [guid]::NewGuid().ToString())
$sumBackup = Join-Path $env:TEMP ("kilhook-go.sum." + [guid]::NewGuid().ToString())
Copy-Item go.mod $modBackup
if (Test-Path go.sum) { Copy-Item go.sum $sumBackup }
$out = & go mod tidy 2>&1
$tidyExit = $LASTEXITCODE
$modSame = -not (Compare-Object (Get-Content go.mod) (Get-Content $modBackup))
$sumSame = $true
if (Test-Path go.sum) {
    if (Test-Path $sumBackup) {
        $sumSame = -not (Compare-Object (Get-Content go.sum) (Get-Content $sumBackup))
    } else { $sumSame = $false }
}
# Always restore the working copy: a tidy run must never be the thing that
# changes the file a developer is about to test.
Copy-Item -Force $modBackup go.mod
if (Test-Path $sumBackup) { Copy-Item -Force $sumBackup go.sum }
Remove-Item -Force $modBackup, $sumBackup -ErrorAction SilentlyContinue
if ($tidyExit -ne 0) {
    Fail "go mod tidy failed:`n$out"
} elseif (-not ($modSame -and $sumSame)) {
    Fail "go.mod/go.sum are not tidy (run 'go mod tidy' and commit the result)"
} else { Write-Host "    ok" -ForegroundColor Green }

# 5. vulnerability scan ------------------------------------------------------
Write-Step "govulncheck ./..."
if (Require-Tool 'govulncheck' 'Install with: go install golang.org/x/vuln/cmd/govulncheck@latest') {
    $out = & govulncheck ./... 2>&1
    if ($LASTEXITCODE -ne 0) { Fail "govulncheck found vulnerabilities (must include kin-openapi >= v0.148.0):`n$out" } else { Write-Host "    ok" -ForegroundColor Green }
}

# 6. dependency rule: internal/* must not import wails ----------------------
Write-Step "dependency rule (internal/* must not import wails)"
$out = & go list -deps ./internal/... 2>&1
if ($LASTEXITCODE -ne 0) { Fail "go list failed:`n$out" } else {
    $hits = $out | Select-String -Pattern 'wails'
    if ($hits) { Fail "internal/* imports wails:`n$hits" } else { Write-Host "    ok" -ForegroundColor Green }
}

# 7. coverage gate on the engine packages --------------------------------
Write-Step "coverage gate (format, spec, diff, fuzz, http, engine >= 80%)"
$gated = @('github.com/24Bit-System/kilhook/internal/format', 'github.com/24Bit-System/kilhook/internal/spec', 'github.com/24Bit-System/kilhook/internal/diff', 'github.com/24Bit-System/kilhook/internal/fuzz', 'github.com/24Bit-System/kilhook/internal/http', 'github.com/24Bit-System/kilhook/internal/engine')
foreach ($pkg in $gated) {
    $out = & go test $pkg -cover -count=1 2>&1
    if ($LASTEXITCODE -ne 0) {
        Fail "tests failed for $pkg`n$out"
        continue
    }
    $line = $out | Select-String -Pattern 'coverage: ([\d.]+)% of statements'
    if (-not $line) {
        Fail "could not read coverage for $pkg"
        continue
    }
    $pct = [double]::Parse($line.Matches[0].Groups[1].Value, [System.Globalization.CultureInfo]::InvariantCulture)
    if ($pct -lt 80) {
        Fail ("{0} coverage is {1}% (minimum 80%)" -f $pkg, $pct)
    } else {
        Write-Host ("    {0}: {1}%" -f $pkg, $pct) -ForegroundColor Green
    }
}

# 8. embedded frontend bundle matches its sources -------------------------
# mtime comparison cannot survive a git checkout (git does not preserve
# timestamps), so the build writes a content hash of every input and the gate
# recomputes it. A fresh clone passes exactly when the bundle is current.
Write-Step "frontend bundle matches its sources (content hash)"
$fe = 'cmd/kh-app/frontend'
$bundle = Get-ChildItem "$fe/dist/assets/*.js" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $bundle) {
    Fail "no built frontend found in $fe/dist/assets (run: npm run build)"
} elseif (Require-Tool 'node' 'Install Node.js, then run npm ci and npm run build in cmd/kh-app/frontend') {
    Push-Location $fe
    try {
        $out = & node scripts/write-source-hash.mjs --check 2>&1
        if ($LASTEXITCODE -ne 0) { Fail "frontend bundle is stale:`n$out" } else { Write-Host ("    ok ({0})" -f $bundle.Name) -ForegroundColor Green }
    } finally {
        Pop-Location
    }
}

# 9. frontend diagnostics ---------------------------------------------------
Write-Step "svelte-check (frontend markup and a11y)"
if (-not (Test-Path (Join-Path $fe 'node_modules'))) {
    Fail "frontend dependencies are not installed (run: npm ci in $fe)"
} elseif (Require-Tool 'npm' 'Install Node.js, then run npm ci in cmd/kh-app/frontend') {
    Push-Location $fe
    try {
        $out = & npm run check --silent 2>&1
        if ($LASTEXITCODE -ne 0) { Fail "svelte-check reported problems:`n$out" } else { Write-Host "    ok" -ForegroundColor Green }
    } finally {
        Pop-Location
    }
}

# 10. frontend unit tests ---------------------------------------------------
Write-Step "frontend unit tests (vitest)"
if (-not (Test-Path (Join-Path $fe 'node_modules'))) {
    Fail "frontend dependencies are not installed (run: npm ci in $fe)"
} elseif (Require-Tool 'npm' 'Install Node.js, then run npm ci in cmd/kh-app/frontend') {
    Push-Location $fe
    try {
        $out = & npm test --silent 2>&1
        if ($LASTEXITCODE -ne 0) { Fail "vitest reported problems:`n$out" } else { Write-Host "    ok" -ForegroundColor Green }
    } finally {
        Pop-Location
    }
}

Complete
