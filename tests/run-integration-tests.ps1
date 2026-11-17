#requires -Version 5.1
<#
.SYNOPSIS
Runs the built plugin against a real SSH server in every transfer mode.

.DESCRIPTION
The harness loads build\bin\<arch>_Release\SFTPplug.wfx and drives it through
the Fs* exports Total Commander uses. Each mode (SFTP, SCP for data,
SCP-only, shell transfer, text line ends) runs as its own session derived
from one profile.

The profile is copied, never modified: either from an sftpplug.ini (default:
the one Total Commander uses) or from explicit -Server/-User/-KeyFile values.
The plugin only ever sees a temporary copy, so fingerprints or paths it
writes back do not touch the original. Session names in the output are
aliases (it-sftp, it-scp, ...) so logs never show a real host name.

Everything the run creates on the server lives in one directory under
-RemoteBase, and only that directory is removed.

.EXAMPLE
.\tests\run-integration-tests.ps1 -Profile wsl2
.\tests\run-integration-tests.ps1 -Server localhost:2222 -User tester -KeyFile .\ci_key -AcceptNewHostKey
#>
param(
    [ValidateSet('x64', 'x86', 'arm64', 'both', 'all', '')] [string]$Arch = '',
    [string]$Profile,
    [string]$IniPath = (Join-Path $env:APPDATA 'GHISLER\sftpplug.ini'),
    [string]$Server,
    [string]$User,
    [string]$KeyFile,
    [string]$RemoteBase = '/tmp',
    [string[]]$Modes = @('sftp', 'scp', 'scponly', 'shell', 'text'),
    [switch]$AcceptNewHostKey,
    [switch]$VerboseLog
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
$Root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $Root 'tools\Toolchain.psm1') -Force

# Default: every architecture this machine can run (x64 and x86 here, all
# three on Windows on Arm). Others are compiled only.
$Archs = @(Resolve-SftpTestArch $Arch)
# "-Modes scponly,shell" arrives as one string through pwsh -File.
$Modes = @($Modes | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$knownModes = 'sftp', 'scp', 'scponly', 'shell', 'text', 'php'
foreach ($m in $Modes) { if ($m -notin $knownModes) { throw "Unknown mode '$m'. Known: $($knownModes -join ', ')" } }
$Latin1 = [System.Text.Encoding]::GetEncoding(28591)  # byte-preserving round trip of an ANSI ini

# ---------------------------------------------------------------------------
# Base profile
# ---------------------------------------------------------------------------
function Read-IniSection([string]$Path, [string]$Section) {
    if (-not (Test-Path -LiteralPath $Path)) { throw "ini not found: $Path" }
    $lines = $Latin1.GetString([System.IO.File]::ReadAllBytes($Path)) -split "`r?`n"
    $result = [ordered]@{}
    $inside = $false
    foreach ($line in $lines) {
        if ($line -match '^\s*\[(.+)\]\s*$') { $inside = ($Matches[1] -eq $Section); continue }
        if ($inside -and $line -match '^\s*([^=;#]+?)\s*=(.*)$') { $result[$Matches[1]] = $Matches[2] }
    }
    if ($result.Count -eq 0) { throw "profile [$Section] not found in $Path" }
    return $result
}

if ($Profile) {
    $base = Read-IniSection $IniPath $Profile
} elseif ($Server -and $User) {
    $base = [ordered]@{ server = $Server; user = $User; transfermode = '0'; utf8 = '1' }
    if ($KeyFile) { $base['privkeyfile'] = (Resolve-Path -LiteralPath $KeyFile).Path }
} else {
    throw 'Pass -Profile <name> or -Server/-User [-KeyFile].'
}

$overrides = @{
    sftp    = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0' }
    scp     = @{ scpfordata = '1'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0' }
    scponly = @{ scpfordata = '1'; scponly = '1'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0' }
    shell   = @{ scpfordata = '1'; scponly = '1'; shelltransfer = '1'; shelltransferforce = '1'; unixlinebreaks = '0' }
    text    = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '1' }
    # PHP Agent: the profile itself says transfermode=1; it has no permissions.
    php     = @{}
}

$iniDir = Join-Path ([System.IO.Path]::GetTempPath()) "sftpplug-it-ini-$PID"
New-Item -ItemType Directory -Path $iniDir -Force | Out-Null
$ini = [System.Text.StringBuilder]::new()
foreach ($mode in $Modes) {
    [void]$ini.AppendLine("[it-$mode]")
    foreach ($key in $base.Keys) {
        if (-not $overrides[$mode].ContainsKey($key)) { [void]$ini.AppendLine("$key=$($base[$key])") }
    }
    foreach ($key in $overrides[$mode].Keys) { [void]$ini.AppendLine("$key=$($overrides[$mode][$key])") }
    [void]$ini.AppendLine()
}
[System.IO.File]::WriteAllBytes((Join-Path $iniDir 'sftpplug.ini'), $Latin1.GetBytes($ini.ToString()))

# ---------------------------------------------------------------------------
# Build the harness and run every mode
# ---------------------------------------------------------------------------
$Toolchain = Get-SftpToolchain -Arch $Archs
$env:SFTP_IT_ACCEPT_NEW_HOSTKEY = if ($AcceptNewHostKey) { '1' } else { '0' }
$env:SFTP_IT_VERBOSE = if ($VerboseLog) { '1' } else { '0' }
# The plugin's own diagnostic log, for when a check fails:
# %LOCALAPPDATA%\SFTPplug\sftpplug.log
$env:SFTPPLUG_DEBUGLOG = '1'

$failures = [System.Collections.Generic.List[string]]::new()
try {
    foreach ($a in $Archs) {
        $platformDir = @{ x64 = 'x64_Release'; x86 = 'Win32_Release'; arm64 = 'ARM64_Release' }[$a]
        $plugin = Join-Path $Root "build\bin\$platformDir\SFTPplug.wfx"
        if (-not (Test-Path -LiteralPath $plugin)) { throw "$plugin not found. Run .\build.ps1 first." }

        # A directory per run, so runs against different servers can overlap.
        $out = Join-Path $PSScriptRoot "out\integration-$a-$PID"
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        $exe = Join-Path $out 'plugin_harness.exe'
        $source = Join-Path $PSScriptRoot 'integration\PluginHarness.cpp'
        $body = "cd /d `"$out`" || exit /b 1`r`ncl /nologo /std:c++20 /EHsc /W4 /WX /permissive- /utf-8 /MT /O2 /DUNICODE /D_UNICODE /I`"$(Join-Path $Root 'src\include')`" `"$source`" /Fe:`"$exe`" || exit /b 2"
        Invoke-SftpDevShellStep -Toolchain $Toolchain -Arch $a -Name "build harness $a" -LogPath (Join-Path $out 'build.log') -Body $body
        if (-not (Test-SftpArchRunnable $a)) {
            Write-Host "  $a : harness compiled; this machine cannot run it - run the tests on Windows on Arm" -ForegroundColor Yellow
            continue
        }

        foreach ($mode in $Modes) {
            Write-Host "=== $a / $mode ===" -ForegroundColor Cyan
            $harnessArgs = @($plugin, $iniDir, "it-$mode", $RemoteBase)
            if ($mode -eq 'text') { $harnessArgs += 'text' }
            if ($mode -eq 'php') { $harnessArgs += 'nochmod' }
            & $exe @harnessArgs
            if ($LASTEXITCODE -ne 0) { $failures.Add("$a/$mode") }
        }
    }
} finally {
    Remove-Item -LiteralPath $iniDir -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($a in $Archs) {
        Remove-Item -LiteralPath (Join-Path $PSScriptRoot "out\integration-$a-$PID") -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($failures.Count) {
    Write-Host "INTEGRATION TESTS FAILED: $($failures -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host 'INTEGRATION TESTS PASSED' -ForegroundColor Green
