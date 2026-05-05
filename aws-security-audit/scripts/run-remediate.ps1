#Requires -Version 5.1
<#
.SYNOPSIS
  Runs remediate.sh via Git Bash (lab only).

.NOTES
  Run AFTER capturing before-scan evidence. Same BUCKET_NAME / REGION / SG_NAME as introduce.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BashScript = Join-Path $ScriptDir "remediate.sh"

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

if (-not $env:BUCKET_NAME -or -not $env:REGION -or -not $env:SG_NAME) {
    Write-Host "ERROR: Set BUCKET_NAME, REGION, and SG_NAME to the SAME values used for introduce-misconfigs.sh" -ForegroundColor Red
    Write-Host "Example:" -ForegroundColor Yellow
    Write-Host '  $env:BUCKET_NAME = "cis-lab-12345"; $env:REGION = "us-east-1"; $env:SG_NAME = "cis-lab-ssh-open"'
    exit 1
}

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    $awsDir = "${env:ProgramFiles}\Amazon\AWSCLIV2"
    if (Test-Path -LiteralPath "$awsDir\aws.exe") {
        $env:Path = "$awsDir;$env:Path"
    }
}

Write-Host "Remediating lab resources for:" -ForegroundColor Cyan
Write-Host "  BUCKET_NAME=$($env:BUCKET_NAME)"
Write-Host "  REGION=$($env:REGION)"
Write-Host "  SG_NAME=$($env:SG_NAME)"

$bash = Find-GitBash
Push-Location $ScriptDir
try {
    & $bash ./remediate.sh
} finally {
    Pop-Location
}
