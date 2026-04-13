# Run in PowerShell from anywhere. Copies SOAR screenshots from Cursor asset cache into this repo.
# Usage: .\docs\copy-screenshots.ps1

$ErrorActionPreference = "Continue"
$RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$Assets = Join-Path $env:USERPROFILE ".cursor\projects\c-Users-Thanmayee-OneDrive-Documents-Desktop-cybersecurity-portfolio\assets"
$ImgOut = Join-Path $RepoRoot "soar-engine\docs\images"
$NextPublic = Join-Path $RepoRoot "cyber-portfolio\public\images"

New-Item -ItemType Directory -Force -Path $ImgOut, $NextPublic | Out-Null

if (-not (Test-Path $Assets)) {
    Write-Host "Assets folder not found: $Assets"
    Write-Host "Manually copy your PNGs to: $ImgOut"
    exit 1
}

$dash = Get-ChildItem $Assets -Filter "*2026-04-12_151540*.png" | Select-Object -First 1
$slack = Get-ChildItem $Assets -Filter "*2026-04-12_151502*.png" | Select-Object -First 1

if ($dash -and (Test-Path -LiteralPath $dash.FullName)) {
    Copy-Item -LiteralPath $dash.FullName (Join-Path $ImgOut "dashboard.png") -Force
    Copy-Item -LiteralPath $dash.FullName (Join-Path $NextPublic "dashboard.png") -Force
    Write-Host "OK dashboard (151540) -> docs/images + cyber-portfolio/public/images/dashboard.png"
} else { Write-Warning "Dashboard PNG not found (*151540*)." }

if ($slack -and (Test-Path -LiteralPath $slack.FullName)) {
    Copy-Item -LiteralPath $slack.FullName (Join-Path $ImgOut "slack-alert.png") -Force
    Copy-Item -LiteralPath $slack.FullName (Join-Path $NextPublic "slack-alert.png") -Force
    Write-Host "OK Slack (151502) -> docs/images + cyber-portfolio/public/images/slack-alert.png"
} else { Write-Warning "Slack PNG not found (*151502*)." }

Write-Host "Done."
