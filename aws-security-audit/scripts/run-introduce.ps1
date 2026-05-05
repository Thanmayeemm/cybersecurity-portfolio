#Requires -Version 5.1
<#
.SYNOPSIS
  Runs introduce-misconfigs.sh via Git Bash (lab only).

.NOTES
  Prerequisites: AWS CLI configured (`aws sts get-caller-identity`), Git for Windows.
  Set GIT_BASH to bash.exe path if Git is not in the default location.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BashScript = Join-Path $ScriptDir "introduce-misconfigs.sh"

function Find-GitBash {
    if ($env:GIT_BASH -and (Test-Path -LiteralPath $env:GIT_BASH)) {
        return $env:GIT_BASH
    }
    $candidates = @(
        "${env:ProgramFiles}\Git\bin\bash.exe",
        "${env:ProgramFiles(x86)}\Git\bin\bash.exe",
        "${env:LocalAppData}\Programs\Git\bin\bash.exe"
    )
    foreach ($p in $candidates) {
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    }
    throw "Git Bash not found. Install Git for Windows or set GIT_BASH to the full path of bash.exe"
}

if (-not (Test-Path -LiteralPath $BashScript)) {
    throw "Missing script: $BashScript"
}

if (-not $env:BUCKET_NAME) {
    $env:BUCKET_NAME = "cis-lab-{0}" -f (Get-Random)
}
if (-not $env:REGION) {
    $env:REGION = "us-east-1"
}
if (-not $env:SG_NAME) {
    $env:SG_NAME = "cis-lab-ssh-open"
}

Write-Host "Lab variables (override by setting env vars before running):" -ForegroundColor Cyan
Write-Host "  BUCKET_NAME=$($env:BUCKET_NAME)"
Write-Host "  REGION=$($env:REGION)"
Write-Host "  SG_NAME=$($env:SG_NAME)"

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    $awsDir = "${env:ProgramFiles}\Amazon\AWSCLIV2"
    if (Test-Path -LiteralPath "$awsDir\aws.exe") {
        $env:Path = "$awsDir;$env:Path"
    }
}

Write-Host "`nChecking AWS identity..." -ForegroundColor Cyan
& aws sts get-caller-identity

$bash = Find-GitBash
Write-Host "`nUsing: $bash" -ForegroundColor Cyan

Push-Location $ScriptDir
try {
    # Environment variables above are inherited by bash.exe
    & $bash ./introduce-misconfigs.sh
} finally {
    Pop-Location
}
