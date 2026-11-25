# Smoke test against public APIs.
#
# Runs the full loop (send -> validate -> fuzz -> diff -> report -> HTML export)
# against three real, read-only services plus the Swagger Petstore with its real
# OpenAPI document. This is the full-loop smoke test, and the only scripted check
# in the repo that uses the network.
#
#   pwsh -File scripts/smoke.ps1
#
# The workspace is a temp directory that is removed when the script finishes,
# whether it succeeds or fails.
param(
    [int]$MaxRequests = 20,
    [double]$RateLimit = 3
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$work = Join-Path ([IO.Path]::GetTempPath()) ("kilhook-smoke-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))

try {
    $specDir = Join-Path $work 'specs'
    $reports = Join-Path $work 'reports'
    New-Item -ItemType Directory -Path $specDir, $reports -Force | Out-Null

    Write-Host "workspace: $work"
    Write-Host "building kh-cli..."
    & go build -o (Join-Path $work 'kh-cli.exe') ./cmd/kh-cli
    if ($LASTEXITCODE -ne 0) { throw "build failed" }
    $cli = Join-Path $work 'kh-cli.exe'

    Write-Host "downloading the petstore OpenAPI document..."
    $specUrl = 'https://petstore3.swagger.io/api/v3/openapi.json'
    $specPath = Join-Path $specDir 'petstore.json'
    # curl, not Invoke-WebRequest: the petstore host answers 403 to the PowerShell
    # user agent and 200 to curl.
    & curl.exe -fsSL -A 'kilhook-smoke/0.1' --max-time 30 -o $specPath $specUrl
    if ($LASTEXITCODE -ne 0) { throw "could not download $specUrl" }

    Copy-Item "$root/testdata/smoke/*.kh" $work

    $cases = @('petstore', 'httpbin', 'jsonplaceholder', 'dummyjson')
    $failures = 0
    $rows = @()

    foreach ($case in $cases) {
        $kh = Join-Path $work "$case.kh"
        $json = Join-Path $work "$case.json"
        $html = Join-Path $reports "$case.html"
        try {
            & $cli run $kh --allow-nonlocal --json --html $html `
                --max-requests $MaxRequests --rate-limit $RateLimit 1> $json 2> (Join-Path $work "$case.err")
            $code = $LASTEXITCODE

            $raw = Get-Content $json -Raw
            if ([string]::IsNullOrWhiteSpace($raw)) {
                throw "empty report (exit $code)"
            }
            $report = $raw | ConvertFrom-Json
            $status = $report.response.status
            # @($null).Count is 1 in PowerShell, which would report a violation for the
            # three cases that have no spec at all.
            $violations = if ($null -eq $report.spec.violations) { 0 } else { @($report.spec.violations).Count }
            $findings = if ($null -eq $report.fuzz.findings) { 0 } else { @($report.fuzz.findings).Count }
            $kinds = (@($report.fuzz.findings) | ForEach-Object { "$($_.kind)/$($_.severity)" } | Sort-Object -Unique) -join ', '
            $htmlBytes = if (Test-Path $html) { (Get-Item $html).Length } else { 0 }
            $rows += [pscustomobject]@{
                case       = $case
                http       = $status
                exit       = $code
                violations = $violations
                findings   = $findings
                kinds      = $kinds
                html_bytes = $htmlBytes
            }
            if ($code -ge 2 -or -not $status -or $status -ge 400) { $failures++ }
        } catch {
            $failures++
            $rows += [pscustomobject]@{
                case       = $case
                http       = $null
                exit       = $LASTEXITCODE
                violations = 0
                findings   = 0
                kinds      = $_.Exception.Message
                html_bytes = 0
            }
        }
    }

    $rows | Format-Table -AutoSize | Out-String | Write-Host
    Write-Host "reports: $reports"
    if ($failures -gt 0) {
        throw "$failures case(s) failed to complete the loop"
    }
    Write-Host "smoke test passed: 4 APIs, spec validation, fuzz, report and HTML export" -ForegroundColor Green
} finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
