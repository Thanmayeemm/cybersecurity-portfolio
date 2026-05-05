#Requires -Version 5.1
<#
.SYNOPSIS
  Run Prowler AWS CIS 2.0 compliance scan with HTML + JSON-OCSF output (UTF-8 safe on Windows).

.PARAMETER ReportLabel
  Output filename prefix (e.g. before-report, after-report).

.PARAMETER OutputDirectory
  Folder for reports. Default: ../reports next to this script.

.EXAMPLE
  ./run-prowler-cis.ps1 -ReportLabel before-report
#>

param(
    [Parameter(Mandatory = $false)]
    [string] $ReportLabel = "prowler-cis",

    [Parameter(Mandatory = $false)]
    [string] $OutputDirectory = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $ScriptDir "..\reports"
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path

chcp 65001 | Out-Null
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python launcher 'py' not found. Install Python 3.11."
}

Write-Host "Output directory: $OutputDirectory" -ForegroundColor Cyan
Write-Host "Report prefix:    $ReportLabel" -ForegroundColor Cyan

# Avoid appending to an existing export (can produce invalid multi-payload files on some hosts).
$patterns = @(
    (Join-Path $OutputDirectory "$ReportLabel.html"),
    (Join-Path $OutputDirectory "$ReportLabel.ocsf.json"),
    (Join-Path $OutputDirectory "compliance\${ReportLabel}_cis_2.0_aws.csv")
)
foreach ($p in $patterns) {
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
}

& py -3.11 -m prowler aws `
    --compliance cis_2.0_aws `
    --output-formats html json-ocsf `
    --output-filename $ReportLabel `
    --output-directory $OutputDirectory `
    -z `
    --no-banner

Write-Host "`nDone. OCSF JSON: $OutputDirectory\$ReportLabel.ocsf.json" -ForegroundColor Green
