#requires -Version 5.1
<#
.SYNOPSIS
Renders every plugin dialog in every language and checks its layout.

.DESCRIPTION
The test executable embeds the plugin's own resources and layout code, so
each dialog is built exactly as the plugin builds it. Failures are clipped
text, overlapping controls and controls outside the dialog; PNG screenshots
go to tests\out\ui\<arch>.

.PARAMETER Arch
x64 (default), x86, arm64, both (x64 + x86) or all. An architecture this
machine cannot run (arm64 on x64) is compiled only.
#>
param([ValidateSet('x64', 'x86', 'arm64', 'both', 'all')] [string]$Arch = 'x64')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
$Root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $Root 'tools\Toolchain.psm1') -Force

$Archs = @(Resolve-SftpTestArch $Arch)
$Toolchain = Get-SftpToolchain -Arch $Archs
$failed = $false
foreach ($a in $Archs) {
    $out = Join-Path $PSScriptRoot "out\ui-$a"
    if (Test-Path $out) { Remove-Item $out -Recurse -Force }
    New-Item -ItemType Directory -Path $out -Force | Out-Null
    $exe = Join-Path $out 'dialog_layout_test.exe'
    $res = Join-Path $out 'sftpplug.res'
    $inc = "/I`"$(Join-Path $Root 'src\include')`""
    $body = @"
cd /d "$(Join-Path $Root 'src\res')" || exit /b 1
rc /nologo $inc /I"$(Join-Path $Root 'src\res')" /fo "$res" sftpplug.rc || exit /b 2
cd /d "$out" || exit /b 3
cl /nologo /std:c++20 /EHsc /W4 /WX /permissive- /utf-8 /MT /O2 /DUNICODE /D_UNICODE $inc "$(Join-Path $PSScriptRoot 'ui\DialogLayoutTest.cpp')" "$(Join-Path $Root 'src\core\DialogLayout.cpp')" "$res" /Fe:"$exe" /link /SUBSYSTEM:CONSOLE /MANIFEST:EMBED /MANIFESTINPUT:"$(Join-Path $PSScriptRoot 'ui\host.manifest')" user32.lib gdi32.lib dwmapi.lib gdiplus.lib || exit /b 4
"@
    Invoke-SftpDevShellStep -Toolchain $Toolchain -Arch $a -Name "build layout test $a" -LogPath (Join-Path $out 'build.log') -Body $body
    if (-not (Test-SftpArchRunnable $a)) {
        Write-Host "  $a : compiled; this machine cannot run it - run the test on Windows on Arm" -ForegroundColor Yellow
        continue
    }
    & $exe (Join-Path $Root 'src\res\language') $out
    if ($LASTEXITCODE -ne 0) { $failed = $true }
}
if ($failed) { Write-Host 'UI LAYOUT TESTS FAILED' -ForegroundColor Red; exit 1 }
Write-Host 'UI LAYOUT TESTS PASSED' -ForegroundColor Green
