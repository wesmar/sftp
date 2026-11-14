#requires -Version 5.1
<#
.SYNOPSIS
Builds and runs the unit tests for x64 and x86.

.DESCRIPTION
Tests are compiled with the same evidence-selected toolchain as the plugin,
with /W4 /WX /permissive-. When the MSVC installation carries a complete
AddressSanitizer runtime for a target, that target's tests are additionally
built and run under ASan.

.PARAMETER Arch
x64, x86 or both (default).

.PARAMETER Filter
Runs only test cases whose name contains this text.
#>
param(
    [ValidateSet('x64', 'x86', 'both')] [string]$Arch = 'both',
    [string]$Filter
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
$Root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $Root 'tools\Toolchain.psm1') -Force

# Production sources exercised by the unit tests, compiled as-is.
$UnitSources = @(
    'src\core\TextConversion.cpp',
    'src\core\PpkConverter.cpp',
    'src\core\TerminalText.cpp',
    'src\core\PasswordCrypto.cpp',
    'src\core\WildcardMatch.cpp'
)
$SystemLibs = 'ws2_32.lib crypt32.lib advapi32.lib user32.lib bcrypt.lib'

$Archs = if ($Arch -eq 'both') { @('x64', 'x86') } else { @($Arch) }
$Toolchain = Get-SftpToolchain -Arch $Archs
Write-SftpToolchainSummary $Toolchain

$testSources = @(Get-ChildItem (Join-Path $PSScriptRoot 'unit') -Filter '*.cpp' | ForEach-Object { "`"$($_.FullName)`"" })
$prodSources = @($UnitSources | ForEach-Object { "`"$(Join-Path $Root $_)`"" })
$common = '/nologo /std:c++20 /EHsc /W4 /WX /permissive- /utf-8 /DUNICODE /D_UNICODE /DNOMINMAX /DWIN32_LEAN_AND_MEAN'
$include = "/I`"$(Join-Path $Root 'src\include')`" /I`"$(Join-Path $PSScriptRoot 'unit')`""

function Test-AsanAvailable([string]$A) {
    $t = $Toolchain.Targets[$A]
    $msvcRoot = Split-Path (Split-Path (Split-Path $t.BinDir -Parent) -Parent) -Parent
    $suffix = if ($A -eq 'x64') { 'x86_64' } else { 'i386' }
    (Test-Path (Join-Path $msvcRoot "lib\$A\clang_rt.asan_dynamic-$suffix.lib")) -and
    (Test-Path (Join-Path $t.BinDir "clang_rt.asan_dynamic-$suffix.dll"))
}

$env:SFTP_TEST_FIXTURES = Join-Path $PSScriptRoot 'fixtures'

$failures = [System.Collections.Generic.List[string]]::new()
foreach ($a in $Archs) {
    $libDir = Join-Path $Root 'src\lib'
    $crypto = Join-Path $libDir "libcrypto_$a.lib"
    $osslInclude = Join-Path $libDir "include-$a"
    if (-not (Test-Path $crypto) -or -not (Test-Path $osslInclude)) {
        throw "OpenSSL for $a is not built. Run .\build-deps.ps1 first."
    }
    $variants = @(@{ Name = 'release'; Flags = '/MT /O2 /DNDEBUG' })
    if (Test-AsanAvailable $a) {
        $variants += @{ Name = 'asan'; Flags = '/MT /Od /Zi /fsanitize=address' }
    } else {
        Write-Host "  $a : AddressSanitizer runtime not installed in this MSVC - ASan pass skipped" -ForegroundColor Yellow
    }

    foreach ($v in $variants) {
        $out = Join-Path $PSScriptRoot "out\$a-$($v.Name)"
        if (Test-Path $out) { Remove-Item $out -Recurse -Force }
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        $exe = Join-Path $out 'unit_tests.exe'
        $body = @"
cd /d "$out" || exit /b 1
cl $common $($v.Flags) $include /I"$osslInclude" $($testSources -join ' ') $($prodSources -join ' ') /Fe:"$exe" /Fo:"$out\\" /link "$crypto" $SystemLibs || exit /b 2
"@
        Invoke-SftpDevShellStep -Toolchain $Toolchain -Arch $a -Name "compile unit tests $a $($v.Name)" -LogPath (Join-Path $out 'build.log') -Body $body

        Write-Host "  running $a $($v.Name)" -ForegroundColor Gray
        $testArgs = if ($Filter) { @($Filter) } else { @() }
        $savedPath = $env:PATH
        if ($v.Name -eq 'asan') { $env:PATH = "$($Toolchain.Targets[$a].BinDir);$env:PATH" }
        try {
            & $exe @testArgs | ForEach-Object { Write-Host "    $_" }
            if ($LASTEXITCODE -ne 0) { $failures.Add("$a $($v.Name)") }
        } finally {
            $env:PATH = $savedPath
        }
    }
}

if ($failures.Count) {
    Write-Host "UNIT TESTS FAILED: $($failures -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host 'UNIT TESTS PASSED' -ForegroundColor Green
