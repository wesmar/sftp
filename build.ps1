#requires -Version 5.1
<#
.SYNOPSIS
Builds SFTPplug (x64 and x86), the help page and the TC install package.

.DESCRIPTION
The toolchain is chosen on evidence by tools\Toolchain.psm1: the platform
toolset, MSVC version, Windows SDK and host architecture passed to MSBuild
are the ones whose compiler, assembler, libraries and headers exist on disk.
Static libraries from build-deps.ps1 are linked only when the manifest proves
they match the current pins and were not replaced since.

.PARAMETER NoHelp      Skip the single-page help.
.PARAMETER NoDeploy    Do not copy the result into Total Commander.
.PARAMETER NoZip       Do not build bin\SFTPplug.zip.
.PARAMETER X64Only     Build only the 64-bit plugin.
#>
param(
    [switch]$NoHelp,
    [switch]$NoDeploy,
    [switch]$NoZip,
    [switch]$X64Only
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
Import-Module (Join-Path $PSScriptRoot 'tools\Toolchain.psm1') -Force

$ProjectName = 'SFTPplug'
$Root        = $PSScriptRoot
$BinDir      = Join-Path $Root 'bin'
$BuildDir    = Join-Path $Root 'build'
$Project     = Join-Path $BuildDir 'SFTPplug.vcxproj'
$LibDir      = Join-Path $Root 'src\lib'
$Manifest    = Join-Path $LibDir 'deps-manifest.json'
$HelpBuilder = Join-Path $Root 'tools\build-help-page.py'
$HelpPage    = Join-Path $BinDir "$ProjectName-help.html"
$PhpAgent    = Join-Path $Root 'src\agent\sftp.php'
$Template    = Join-Path $Root 'src\res\sftpplug.tpl'
$LanguageDir = Join-Path $Root 'src\res\language'
$Readme      = Join-Path $Root 'src\help\readme.txt'

$Archs = if ($X64Only) { @('x64') } else { @('x64', 'x86') }
$OutputDir = @{
    x64 = Join-Path $BuildDir 'bin\x64_Release'
    x86 = Join-Path $BuildDir 'bin\Win32_Release'
}

function Write-Section([string]$Title) { Write-Host ''; Write-Host "--- $Title ---" -ForegroundColor Cyan }
function Write-Step([string]$Text)     { Write-Host "  $Text" -ForegroundColor Gray }
function Write-Ok([string]$Text)       { Write-Host "  $Text" -ForegroundColor Green }

$PluginVersion = '0.0.0.0'
if ((Get-Content (Join-Path $Root 'src\include\version.h') -Raw) -match '#define\s+VER_FILEVERSION_STR\s+"([^"]+)"') {
    $PluginVersion = $Matches[1]
}
Write-Host "--- $ProjectName $PluginVersion ---" -ForegroundColor Cyan

# ============================================================================
# Toolchain and dependencies
# ============================================================================
Write-Section 'Toolchain'
$Toolchain = Get-SftpToolchain -Arch $Archs
Write-SftpToolchainSummary $Toolchain

Write-Section 'Dependencies'
if (-not (Test-Path -LiteralPath $Manifest)) {
    throw "src\lib\deps-manifest.json not found. Run .\build-deps.ps1 first."
}
$manifestTargets = (Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json).targets
$expectedDigest = Get-SftpDependencyDigest
foreach ($a in $Archs) {
    $entry = $manifestTargets.PSObject.Properties[$a]
    if (-not $entry) { throw "No $a libraries recorded. Run .\build-deps.ps1." }
    if ($entry.Value.digest -ne $expectedDigest) {
        throw "The $a libraries were built from different pins or patches. Run .\build-deps.ps1."
    }
    foreach ($lib in $entry.Value.libraries.PSObject.Properties) {
        $path = Join-Path $LibDir $lib.Name
        if (-not (Test-Path -LiteralPath $path) -or
            (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant() -ne $lib.Value) {
            throw "$($lib.Name) does not match the manifest. Run .\build-deps.ps1."
        }
    }
    Write-Ok "$a : $($entry.Value.openssl.Split(' ')[0]) OpenSSL, $($entry.Value.libssh2.Split(' ')[0]) - verified"
}

# ============================================================================
# Build metadata
# ============================================================================
# Taken from git, never from the clock, so two builds of one commit come out
# byte for byte the same. "-dirty" marks a tree with uncommitted changes.
Write-Section 'Build metadata'
$BuildInfoGen = Join-Path $Root 'src\include\build_info_gen.h'
$git = Get-Command git -ErrorAction SilentlyContinue
$sha = if ($git) { (& git -C $Root rev-parse --short=7 HEAD 2>$null) } else { $null }
if ($sha) {
    $tag  = (& git -C $Root describe --tags --always 2>$null)
    $date = (& git -C $Root log -1 --format=%cs 2>$null)
    if (& git -C $Root status --porcelain --untracked-files=no 2>$null) { $sha += '-dirty' }
    $header = "#pragma once`r`n#define SFTP_BUILD_TAG  `"$tag`"`r`n#define SFTP_BUILD_SHA  `"$sha`"`r`n#define SFTP_BUILD_DATE `"$date`"`r`n"
    # Rewritten only on change, so an unchanged tree does not recompile.
    $current = if (Test-Path -LiteralPath $BuildInfoGen) { [System.IO.File]::ReadAllText($BuildInfoGen) } else { '' }
    if ($current -ne $header) { [System.IO.File]::WriteAllText($BuildInfoGen, $header, [System.Text.Encoding]::ASCII) }
    Write-Ok "$tag $sha $date"
} else {
    if (Test-Path -LiteralPath $BuildInfoGen) { Remove-Item -LiteralPath $BuildInfoGen -Force }
    Write-Host '  not a git checkout - the plugin labels itself "local"' -ForegroundColor Yellow
}

# ============================================================================
# Build
# ============================================================================
New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
foreach ($a in $Archs) {
    $t = $Toolchain.Targets[$a]
    Write-Section "Release $a"
    if (Test-Path -LiteralPath $OutputDir[$a]) { Remove-Item -LiteralPath $OutputDir[$a] -Recurse -Force }
    $msbuildArgs = @(
        $Project, '/t:Rebuild', '/m', '/nologo', '/v:m',
        '/p:Configuration=Release',
        "/p:Platform=$($t.MSBuildPlatform)",
        "/p:PlatformToolset=$($t.PlatformToolset)",
        "/p:VCToolsVersion=$($t.MsvcVersion)",
        "/p:WindowsTargetPlatformVersion=$($Toolchain.WindowsSdk.Version)",
        "/p:PreferredToolArchitecture=$($t.HostArch)"
    )
    & $Toolchain.MSBuild @msbuildArgs
    if ($LASTEXITCODE -ne 0) { throw "MSBuild failed for $a (exit $LASTEXITCODE)" }
    $wfx = Join-Path $OutputDir[$a] "$ProjectName.wfx"
    if (-not (Test-Path -LiteralPath $wfx)) { throw "MSBuild reported success but $wfx is missing" }
    Write-Ok ("$ProjectName.wfx ($a) {0:N0} KB" -f ((Get-Item -LiteralPath $wfx).Length / 1KB))
}

# ============================================================================
# Help page (one self-contained HTML file; needs only Python)
# ============================================================================
if (-not $NoHelp) {
    Write-Section 'Help page'
    $python = Find-SftpBuildTool -Name 'Python' -Executable 'python.exe' -Candidates @() -Validate {
        param($p) (& $p -c 'import sys; print(sys.version_info[0])' 2>$null) -eq '3'
    }
    if (-not $python) { throw 'Python 3 not found (needed for the help page). Install it or pass -NoHelp.' }
    & $python $HelpBuilder $HelpPage
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $HelpPage)) { throw 'Help page build failed' }
    Write-Ok ("$ProjectName-help.html {0:N0} KB" -f ((Get-Item -LiteralPath $HelpPage).Length / 1KB))
}

# ============================================================================
# Package
# ============================================================================
function Get-PackageFiles {
    $files = [ordered]@{}
    $files["$ProjectName.wfx64"] = Join-Path $OutputDir['x64'] "$ProjectName.wfx"
    if (-not $X64Only) { $files["$ProjectName.wfx"] = Join-Path $OutputDir['x86'] "$ProjectName.wfx" }
    $files['sftp.php'] = $PhpAgent
    $files['sftpplug.tpl'] = $Template
    $files['readme.txt'] = $Readme
    if (Test-Path -LiteralPath $HelpPage) { $files["$ProjectName-help.html"] = $HelpPage }
    foreach ($lng in Get-ChildItem -LiteralPath $LanguageDir -Filter '*.lng') { $files["language\$($lng.Name)"] = $lng.FullName }
    return $files
}

if (-not $NoZip) {
    Write-Section 'Package'
    $zipPath = Join-Path $BinDir "$ProjectName.zip"
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    $pluginstInf = "[plugininstall]`r`ndescription=Secure FTP plugin (x64+x86) - static build, no external DLL required`r`n" +
                   "type=wfx`r`nfile=$ProjectName.wfx`r`nfile64=$ProjectName.wfx64`r`ndefaultdir=$ProjectName`r`nversion=$PluginVersion`r`n"

    Add-Type -AssemblyName System.IO.Compression
    $stream = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::CreateNew)
    $zip = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $inf = $zip.CreateEntry('pluginst.inf', [System.IO.Compression.CompressionLevel]::Optimal).Open()
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($pluginstInf)
        try { $inf.Write($bytes, 0, $bytes.Length) } finally { $inf.Dispose() }
        foreach ($item in (Get-PackageFiles).GetEnumerator()) {
            if (-not (Test-Path -LiteralPath $item.Value)) { throw "package input missing: $($item.Value)" }
            $dst = $zip.CreateEntry($item.Key, [System.IO.Compression.CompressionLevel]::Optimal).Open()
            $src = [System.IO.File]::OpenRead($item.Value)
            try { $src.CopyTo($dst) } finally { $src.Dispose(); $dst.Dispose() }
        }
    } finally {
        $zip.Dispose()
        $stream.Dispose()
    }
    Write-Ok ("$ProjectName.zip {0:N0} KB" -f ((Get-Item -LiteralPath $zipPath).Length / 1KB))
}

# ============================================================================
# Deploy into Total Commander
# ============================================================================
function Get-TotalCommanderPath {
    foreach ($hive in 'HKCU:', 'HKLM:') {
        $dir = (Get-ItemProperty -Path "$hive\Software\Ghisler\Total Commander" -ErrorAction SilentlyContinue).InstallDir
        if ($dir -and (Test-Path -LiteralPath $dir)) { return $dir }
    }
    foreach ($dir in 'C:\totalcmd', "$env:ProgramFiles\totalcmd", "${env:ProgramFiles(x86)}\totalcmd") {
        if (Test-Path -LiteralPath (Join-Path $dir 'TOTALCMD64.EXE')) { return $dir }
    }
    return $null
}

if (-not $NoDeploy) {
    Write-Section 'Deploy'
    $tc = Get-TotalCommanderPath
    if (-not $tc) {
        Write-Host '  Total Commander not found - deploy skipped' -ForegroundColor Yellow
    } else {
        # The plugin DLLs are locked while Total Commander runs. It is asked to
        # close, never killed: a dialog or a running copy may be holding it,
        # and those are the user's to finish.
        $running = @(Get-Process -Name 'TOTALCMD', 'TOTALCMD64' -ErrorAction SilentlyContinue)
        $restart = @($running | ForEach-Object { $_.Path } | Where-Object { $_ } | Select-Object -Unique)
        if ($running.Count) {
            Write-Step "closing $($running.Count) Total Commander process(es)"
            $running | ForEach-Object { $_.CloseMainWindow() | Out-Null }
            $stillOpen = @($running | Where-Object { -not $_.WaitForExit(20000) })
            if ($stillOpen.Count) {
                Write-Host '  Total Commander did not close (a dialog or a copy may be open) - deploy skipped.' -ForegroundColor Yellow
                Write-Host '  The build is complete; close Total Commander and run .\build.ps1 again to deploy.' -ForegroundColor Yellow
                $tc = $null
            }
        }
        if ($tc) {
            $pluginDir = Join-Path $tc "plugins\wfx\$ProjectName"
            New-Item -ItemType Directory -Path (Join-Path $pluginDir 'language') -Force | Out-Null
            foreach ($item in (Get-PackageFiles).GetEnumerator()) {
                Copy-Item -LiteralPath $item.Value -Destination (Join-Path $pluginDir $item.Key) -Force
            }
            Write-Ok "deployed to $pluginDir"
            foreach ($exe in $restart) {
                Start-Process -FilePath $exe
                Write-Ok "restarted $(Split-Path $exe -Leaf)"
            }
        }
    }
}

Write-Host ''
Write-Host "BUILD COMPLETED - $ProjectName $PluginVersion" -ForegroundColor Green
