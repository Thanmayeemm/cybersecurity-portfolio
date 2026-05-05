#Requires -Version 5.1
<#
.SYNOPSIS
  PHASE 3–4 (after Root MFA enabled): CIS Prowler scan, sanitized JSON export, metrics, optional redaction.

  Run from repo root OR scripts folder after confirming root MFA in the AWS Console.
#>

param(
    [switch] $SkipRedaction
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Reports = Join-Path $Root "reports"
$Scripts = Join-Path $Root "scripts"

chcp 65001 | Out-Null
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

& (Join-Path $Scripts "run-prowler-cis.ps1") -ReportLabel after-report -OutputDirectory $Reports

$sanitizer = Join-Path $Scripts "sanitize_prowler_ocsf.py"
$parser = Join-Path $Scripts "parse_prowler_ocsf.py"
$redactor = Join-Path $Scripts "redact_aws_identifiers.py"

& py -3.11 $sanitizer (Join-Path $Reports "after-report.ocsf.json") (Join-Path $Reports "after-report.json")
& py -3.11 $parser (Join-Path $Reports "after-report.json") |
    Set-Content -Encoding utf8 (Join-Path $Reports "after-metrics.json")

if (-not $SkipRedaction -and (Test-Path -LiteralPath $redactor)) {
    foreach ($f in @("after-report.json", "after-metrics.json", "after-report.ocsf.json", "after-report.html")) {
        $full = Join-Path $Reports $f
        if (Test-Path -LiteralPath $full) { & py -3.11 $redactor $full }
    }
}

Write-Host "`nAfter scan complete. Update audit-report.md comparison from reports/after-metrics.json and before-metrics.json." -ForegroundColor Green
