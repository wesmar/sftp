#requires -Version 5.1
<#
.SYNOPSIS
Builds the plugin and runs every test suite: the check before a release.

.DESCRIPTION
Runs, in order: build.ps1 (no deploy, no package), the unit tests, the dialog
layout tests and - for each profile named - the integration tests against a
live server. Every step runs even when an earlier one failed, and a summary
lists them all at the end. The exit code is 0 only when everything passed.

.PARAMETER Profiles
Sections of sftpplug.ini to run the integration tests against, e.g. wsl2.
None given: the integration tests are skipped.

.PARAMETER SkipBuild
Test the binaries already in build\bin.

.PARAMETER SkipPhp
Skip the PHP Agent tests, which otherwise run whenever php.exe is found
(on PATH, in C:\inetpub\php or in C:\php).

.PARAMETER LanPairHost
Another Windows computer to run LAN Pair against (run-lanpair-remote-test.ps1:
ssh and C$ with administrator rights there). None given: skipped.

.EXAMPLE
.\tests\run-all-tests.ps1 -Profiles wsl2 -LanPairHost other-pc
#>
param(
    [string[]]$Profiles = @(),
    [switch]$SkipBuild,
    [switch]$SkipPhp,
    [string]$LanPairHost
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
$Root = Split-Path $PSScriptRoot -Parent
$results = [System.Collections.Generic.List[object]]::new()

function Invoke-Step([string]$Name, [string]$Script, [string[]]$Arguments) {
    Write-Host ''
    Write-Host "=== $Name ===" -ForegroundColor Cyan
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    & pwsh -NoProfile -File $Script @Arguments
    $ok = $LASTEXITCODE -eq 0
    $results.Add([pscustomobject]@{ Step = $Name; Result = $(if ($ok) { 'passed' } else { 'FAILED' }); Time = $watch.Elapsed.ToString('mm\:ss') })
}

if (-not $SkipBuild) {
    Invoke-Step 'build' (Join-Path $Root 'build.ps1') @('-NoDeploy', '-NoZip')
}
Invoke-Step 'unit tests' (Join-Path $PSScriptRoot 'run-unit-tests.ps1') @()
Invoke-Step 'dialog layout tests' (Join-Path $PSScriptRoot 'run-ui-tests.ps1') @()
$phpFound = (Get-Command php.exe -ErrorAction SilentlyContinue) -or
            (Test-Path 'C:\inetpub\php\php.exe') -or (Test-Path 'C:\php\php.exe')
if (-not $SkipPhp -and $phpFound) {
    Invoke-Step 'PHP Agent (protocol + plugin)' (Join-Path $PSScriptRoot 'run-php-agent-tests.ps1') @()
}
foreach ($p in $Profiles) {
    Invoke-Step "integration ($p)" (Join-Path $PSScriptRoot 'run-integration-tests.ps1') @('-Profile', $p)
}
if ($LanPairHost) {
    Invoke-Step 'LAN Pair between two computers' (Join-Path $PSScriptRoot 'run-lanpair-remote-test.ps1') @('-RemoteHost', $LanPairHost)
}

Write-Host ''
$results | Format-Table -AutoSize | Out-String | Write-Host
if (-not $Profiles.Count) {
    Write-Host 'Integration tests skipped: pass -Profiles <sftpplug.ini section> to run them.' -ForegroundColor Yellow
}
$failed = @($results | Where-Object Result -ne 'passed')
if ($failed.Count) {
    Write-Host "FAILED: $(($failed | ForEach-Object Step) -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host 'ALL CHECKS PASSED' -ForegroundColor Green
