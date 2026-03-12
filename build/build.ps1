param(
    [switch]$en,
    [switch]$pl,
    [switch]$de,
    [switch]$fr,
    [switch]$es
)

$projectName = "SFTPplug"
$binDir = Join-Path $PSScriptRoot "bin"
$installerTemplateDir = Join-Path $PSScriptRoot "installer"
$installerDir = Join-Path $binDir "installer"
$installerZip = Join-Path $binDir "sftpplug-installer.zip"
$tcInstallerDir = Join-Path $binDir "tc-installer"
$tcInstallerZip = Join-Path $binDir "sftpplug.zip"
$packagePluginDir = Join-Path $installerDir "plugins\wfx\sftpplug"
$deployPluginDir = "C:\totalcmd\plugins\wfx\sftpplug"
$phpAgentSource = Join-Path $PSScriptRoot "..\src\agent\sftp.php"
$helpSourceDir = Join-Path $PSScriptRoot "..\docs\chm"
$helpProject = Join-Path $helpSourceDir "sftpplug.hhp"
$helpCompiled = Join-Path $helpSourceDir "sftpplug.chm"
$preserveDir = Join-Path $PSScriptRoot ".preserve"
$preserveShellPhp = Join-Path $preserveDir "shell.php"
$resourceScriptPath = Join-Path $PSScriptRoot "..\src\res\sftpplug.rc"
$resourceScriptBackup = Join-Path $preserveDir "sftpplug.rc.original"

function Select-ResourceLanguage {
    param(
        [Parameter(Mandatory = $true)][string]$LanguageCode
    )

    if ($LanguageCode -eq "all") {
        return
    }

    if (-not (Test-Path $resourceScriptPath)) {
        throw "Resource script not found: $resourceScriptPath"
    }

    New-Item -ItemType Directory -Path $preserveDir -Force | Out-Null
    Copy-Item -Path $resourceScriptPath -Destination $resourceScriptBackup -Force

    $rcEncoding = [System.Text.Encoding]::GetEncoding(1250)
    $content = [System.IO.File]::ReadAllText($resourceScriptPath, $rcEncoding)

    $languageSections = @{
        en = @{
            marker  = "// English (U.S.) resources"
            pattern = "(?s)\r?\n?/////////////////////////////////////////////////////////////////////////////\r?\n// English \(U\.S\.\) resources.*?#endif\s*// English \(U\.S\.\) resources\r?\n?"
        }
        pl = @{
            marker  = "// Polish resources"
            pattern = "(?s)\r?\n?/////////////////////////////////////////////////////////////////////////////\r?\n// Polish resources.*?#endif\s*// Polish resources\r?\n?"
        }
        de = @{
            marker  = "// German resources"
            pattern = "(?s)\r?\n?/////////////////////////////////////////////////////////////////////////////\r?\n// German resources.*?#endif\s*// German resources\r?\n?"
        }
        fr = @{
            marker  = "// French resources"
            pattern = "(?s)\r?\n?/////////////////////////////////////////////////////////////////////////////\r?\n// French resources.*?#endif\s*// French resources\r?\n?"
        }
        es = @{
            marker  = "// Spanish resources"
            pattern = "(?s)\r?\n?/////////////////////////////////////////////////////////////////////////////\r?\n// Spanish resources.*?#endif\s*// Spanish resources\r?\n?"
        }
    }

    $iconsBlock = @"
/////////////////////////////////////////////////////////////////////////////
//
// Icons
//

// Icon with lowest ID value placed first to ensure application icon
// remains consistent on all systems.
IDI_ICON0               ICON    DISCARDABLE     "iconconnection.ico"
IDI_ICON1               ICON    DISCARDABLE     "icon1.ico"
IDI_ICON2               ICON    DISCARDABLE     "icon2.ico"
IDI_ICON1SMALL          ICON    DISCARDABLE     "icon3.ico"
IDI_ICON2SMALL          ICON    DISCARDABLE     "icon4.ico"

"@

    if (-not $languageSections.ContainsKey($LanguageCode)) {
        throw "Unsupported language code: $LanguageCode"
    }

    $target = $languageSections[$LanguageCode]
    if ($content -notmatch [Regex]::Escape($target.marker)) {
        throw "Requested language section not found in RC: $($target.marker)"
    }

    foreach ($entry in $languageSections.GetEnumerator()) {
        if ($entry.Key -eq $LanguageCode) {
            continue
        }
        $content = [System.Text.RegularExpressions.Regex]::Replace(
            $content,
            $entry.Value.pattern,
            "",
            [System.Text.RegularExpressions.RegexOptions]::Singleline
        )
    }

    if ($LanguageCode -eq "pl" -or $LanguageCode -eq "de" -or $LanguageCode -eq "fr" -or $LanguageCode -eq "es") {
        
        # In the source RC, icon resources are placed in the EN section.
        # Ensure they are still present for non-EN single-language builds.
        if ($content -notmatch "IDI_ICON0\s+ICON") {
            $polishMarker = [System.Text.RegularExpressions.Regex]::Match(
                $content,
                "/////////////////////////////////////////////////////////////////////////////\r?\n// .* resources",
                [System.Text.RegularExpressions.RegexOptions]::Singleline
            )
            if ($polishMarker.Success) {
                $content = $content.Insert($polishMarker.Index, $iconsBlock + "`r`n")
            } else {
                $content += "`r`n" + $iconsBlock + "`r`n"
            }
        }
    }

    foreach ($entry in $languageSections.GetEnumerator()) {
        if ($entry.Key -eq $LanguageCode) {
            continue
        }
        if ($content -match [Regex]::Escape($entry.Value.marker)) {
            throw "Language selection failed: extra block still present ($($entry.Value.marker))."
        }
    }

    [System.IO.File]::WriteAllText($resourceScriptPath, $content, $rcEncoding)
    Write-Host "Applied resource language filter: $LanguageCode" -ForegroundColor Gray
}

function Restore-ResourceLanguage {
    if (Test-Path $resourceScriptBackup) {
        Copy-Item -Path $resourceScriptBackup -Destination $resourceScriptPath -Force
        Remove-Item $resourceScriptBackup -Force -ErrorAction SilentlyContinue
    }
}

function Remove-PathSafe {
    param(
        [Parameter(Mandatory = $true)][string]$PathToRemove
    )
    if (-not (Test-Path $PathToRemove)) {
        return $true
    }
    try {
        Remove-Item $PathToRemove -Recurse -Force -ErrorAction Stop
        return $true
    } catch {
        Write-Host "  Warning: could not remove $PathToRemove" -ForegroundColor Yellow
        Write-Host "  $($_.Exception.Message)" -ForegroundColor DarkGray
        return $false
    }
}

$buildLanguage = "all"
$selectedLanguageFlags = @()
if ($en) { $selectedLanguageFlags += "en" }
if ($pl) { $selectedLanguageFlags += "pl" }
if ($de) { $selectedLanguageFlags += "de" }
if ($fr) { $selectedLanguageFlags += "fr" }
if ($es) { $selectedLanguageFlags += "es" }
if ($selectedLanguageFlags.Count -gt 1) {
    Write-Error "Use only one language switch: -en, -pl, -de, -fr or -es."
    exit 1
}
if ($selectedLanguageFlags.Count -eq 1) { $buildLanguage = $selectedLanguageFlags[0] }

Write-Host "--- Localizing latest Visual Studio Build Tools ---" -ForegroundColor Cyan
Write-Host "Resource language mode: $buildLanguage" -ForegroundColor Gray

# Find the newest installed Visual Studio instance (including Preview/Next)
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = &$vswhere -latest -prerelease -requires Microsoft.Component.MSBuild -property installationPath

if (-not $vsPath) {
    Write-Error "Latest Visual Studio installation was not found. Check your setup."
    exit 1
}

$msbuild = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"
$vcToolsRoot = Join-Path $vsPath "VC\Tools\MSVC"
$vcToolsVersion = $null
if (Test-Path $vcToolsRoot) {
    $vcToolsVersion = Get-ChildItem $vcToolsRoot -Directory |
        Sort-Object Name -Descending |
        Select-Object -First 1 -ExpandProperty Name
}

Write-Host "Using MSBuild from: $vsPath" -ForegroundColor Gray
Write-Host "Project: $projectName" -ForegroundColor Gray
if ($vcToolsVersion) {
    Write-Host "Using VC tools version: $vcToolsVersion" -ForegroundColor Gray

    $minimumVcToolsVersion = [version]"14.50.0.0"
    $currentVcToolsVersion = [version]("$vcToolsVersion.0")
    if ($currentVcToolsVersion -lt $minimumVcToolsVersion) {
        Write-Error "Detected VC tools $vcToolsVersion, but project requires >= 14.50 (VS 2026 toolset)."
        exit 1
    }
}

# 1. Prepare a clean bin directory
# Preserve custom shell.php from build\bin across clean builds.
if (Test-Path (Join-Path $binDir "shell.php")) {
    New-Item -ItemType Directory -Path $preserveDir -Force | Out-Null
    Copy-Item -Path (Join-Path $binDir "shell.php") -Destination $preserveShellPhp -Force
}

if (-not (Remove-PathSafe -PathToRemove $binDir)) {
    Write-Host "  Continuing with existing bin directory (some files may be locked)." -ForegroundColor Yellow
}
if (-not (Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir | Out-Null
}

if (Test-Path $preserveShellPhp) {
    Copy-Item -Path $preserveShellPhp -Destination (Join-Path $binDir "shell.php") -Force
}

# 2. Build (Release | x64)
Write-Host ""
Write-Host "--- Building Release x64 ---" -ForegroundColor Cyan
Select-ResourceLanguage -LanguageCode $buildLanguage

$msBuildArgs = @(
    "$projectName.vcxproj",
    "/t:Rebuild",
    "/p:Configuration=Release",
    "/p:Platform=x64",
    "/p:PlatformToolset=v145",
    "/p:WindowsTargetPlatformVersion=10.0",
    "/p:DebugSymbols=false",
    "/p:DebugType=none",
    "/m",
    "/nologo",
    "/v:m"
)
if ($vcToolsVersion) {
    $msBuildArgs += "/p:VCToolsVersion=$vcToolsVersion"
}

$msbuildExitCode = 0
try {
    &$msbuild $msBuildArgs
    $msbuildExitCode = $LASTEXITCODE
} finally {
    Restore-ResourceLanguage
}

if ($msbuildExitCode -ne 0) {
    Write-Host ""
    Write-Host "!!! BUILD FAILED !!!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Check the errors above. Common issues:" -ForegroundColor Yellow
    Write-Host "  - Missing plugin headers in src/include" -ForegroundColor Yellow
    Write-Host "  - Missing Windows SDK 10.0" -ForegroundColor Yellow
    Write-Host "  - Visual Studio 2026 (v145) not installed" -ForegroundColor Yellow
    exit $msbuildExitCode
}

# 3. Copy final binaries to bin folder
Write-Host ""
Write-Host "--- Finalizing binaries ---" -ForegroundColor Yellow

$outX64 = Join-Path $PSScriptRoot "bin\x64_Release\$projectName.wfx"

if (Test-Path $outX64) {
    Copy-Item -Path $outX64 -Destination "$binDir\sftpplug.wfx64" -Force
    Write-Host "  x64 binary: $binDir\sftpplug.wfx64" -ForegroundColor Green
} else {
    Write-Host "Warning: x64 output was not found" -ForegroundColor Yellow
    exit 1
}

if (Test-Path $phpAgentSource) {
    Copy-Item -Path $phpAgentSource -Destination "$binDir\sftp.php" -Force
    Write-Host "  PHP agent:  $binDir\sftp.php" -ForegroundColor Green
}

# Compile CHM help (optional) when HTML Help Workshop is installed.
$hhcExe = $null
$hhcCandidates = @(
    (Join-Path ${env:ProgramFiles(x86)} "HTML Help Workshop\hhc.exe"),
    (Join-Path $env:ProgramFiles "HTML Help Workshop\hhc.exe")
)
foreach ($candidate in $hhcCandidates) {
    if (Test-Path $candidate) {
        $hhcExe = $candidate
        break
    }
}

if ($hhcExe -and (Test-Path $helpProject)) {
    if (Test-Path $helpCompiled) {
        Remove-Item $helpCompiled -Force -ErrorAction SilentlyContinue
    }
    Push-Location $helpSourceDir
    try {
        & $hhcExe $helpProject | Out-Null
    } finally {
        Pop-Location
    }
    if (Test-Path $helpCompiled) {
        Copy-Item -Path $helpCompiled -Destination "$binDir\sftpplug.chm" -Force
        Write-Host "  CHM help:   $binDir\sftpplug.chm" -ForegroundColor Green
    } else {
        Write-Host "  Warning: CHM compile did not produce sftpplug.chm" -ForegroundColor Yellow
    }
} elseif (Test-Path $helpCompiled) {
    Copy-Item -Path $helpCompiled -Destination "$binDir\sftpplug.chm" -Force
    Write-Host "  CHM help:   $binDir\sftpplug.chm (prebuilt)" -ForegroundColor Green
} elseif (Test-Path $helpProject) {
    Write-Host "  CHM help skipped (hhc.exe not found). Install HTML Help Workshop for CHM build." -ForegroundColor Yellow
}

# 4b. Auto-deploy binaries to local Total Commander plugin directory
Write-Host ""
Write-Host "--- Auto-deploy to Total Commander plugin dir ---" -ForegroundColor Yellow
if (-not (Test-Path $deployPluginDir)) {
    New-Item -ItemType Directory -Path $deployPluginDir -Force | Out-Null
}

# Close Total Commander before deploy to avoid file locks on plugin binaries.
$tcProcesses = @("TOTALCMD64", "TOTALCMD")
foreach ($procName in $tcProcesses) {
    try {
        Get-Process -Name $procName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction Stop
        Write-Host "  Stopped process: $procName" -ForegroundColor DarkGray
    } catch {
        # Ignore when process is not running.
    }
}
Start-Sleep -Milliseconds 300

$deployFailed = $false
try {
    Copy-Item -Path "$binDir\sftpplug.wfx64" -Destination (Join-Path $deployPluginDir "sftpplug.wfx64") -Force -ErrorAction Stop
    Write-Host "  Deployed x64:   $(Join-Path $deployPluginDir 'sftpplug.wfx64')" -ForegroundColor Green
    if (Test-Path "$binDir\sftpplug.chm") {
        Copy-Item -Path "$binDir\sftpplug.chm" -Destination (Join-Path $deployPluginDir "sftpplug.chm") -Force -ErrorAction Stop
        Write-Host "  Deployed help:  $(Join-Path $deployPluginDir 'sftpplug.chm')" -ForegroundColor Green
    }
    if (Test-Path "$binDir\sftp.php") {
        Copy-Item -Path "$binDir\sftp.php" -Destination (Join-Path $deployPluginDir "sftp.php") -Force -ErrorAction Stop
        Write-Host "  Deployed PHP:   $(Join-Path $deployPluginDir 'sftp.php')" -ForegroundColor Green
    }
    Remove-Item (Join-Path $deployPluginDir "sftp_php74.php") -Force -ErrorAction SilentlyContinue
} catch {
    $deployFailed = $true
    Write-Host "  Failed to deploy x64 (file may be locked by running TOTALCMD64.EXE)." -ForegroundColor Red
    Write-Host "  $_" -ForegroundColor DarkGray
}

if ($deployFailed) {
    Write-Host "  Auto-deploy completed with errors. Zamknij Total Commandera i uruchom build ponownie." -ForegroundColor Yellow
}

# Copy argon2.dll if present in project root (needed for PPK v3 conversion)
$argon2Dll = Join-Path $PSScriptRoot "..\argon2.dll"
if (Test-Path $argon2Dll) {
    Copy-Item -Path $argon2Dll -Destination "$binDir\argon2.dll" -Force
    Write-Host "  Copied argon2.dll to $binDir" -ForegroundColor Green
}

# 4. Build installer package (click-to-install)
Write-Host ""
Write-Host "--- Preparing installer package ---" -ForegroundColor Cyan

if (Test-Path $installerDir) {
    Remove-PathSafe -PathToRemove $installerDir | Out-Null
}
New-Item -ItemType Directory -Path $installerDir | Out-Null
New-Item -ItemType Directory -Path $packagePluginDir -Force | Out-Null

Copy-Item -Path "$binDir\sftpplug.wfx64" -Destination "$packagePluginDir\sftpplug.wfx64" -Force
if (Test-Path "$binDir\sftp.php") {
    Copy-Item -Path "$binDir\sftp.php" -Destination "$packagePluginDir\sftp.php" -Force
}
if (Test-Path "$binDir\sftpplug.chm") {
    Copy-Item -Path "$binDir\sftpplug.chm" -Destination "$packagePluginDir\sftpplug.chm" -Force
}
Copy-Item -Path (Join-Path $installerTemplateDir "install_sftp_plugin.ps1") -Destination (Join-Path $installerDir "install_sftp_plugin.ps1") -Force
Copy-Item -Path (Join-Path $installerTemplateDir "install_sftp_plugin.cmd") -Destination (Join-Path $installerDir "install_sftp_plugin.cmd") -Force
Copy-Item -Path (Join-Path $installerTemplateDir "README_INSTALL.txt") -Destination (Join-Path $installerDir "README_INSTALL.txt") -Force

# Optional runtime DLLs if present next to script template
$optionalDlls = @(
    "libssh2.dll",
    "libcrypto-3-x64.dll",
    "libssl-3-x64.dll",
    "libcrypto-3.dll",
    "libssl-3.dll",
    "libcrypto.dll",
    "libssl.dll",
    "argon2.dll"
)
foreach ($dll in $optionalDlls) {
    $dllPath = Join-Path $installerTemplateDir $dll
    if (Test-Path $dllPath) {
        Copy-Item -Path $dllPath -Destination (Join-Path $packagePluginDir $dll) -Force
        Write-Host "  Included optional runtime: $dll" -ForegroundColor Gray
    }
}

if (Test-Path $installerZip) {
    Remove-Item $installerZip -Force
}
Compress-Archive -Path (Join-Path $installerDir "*") -DestinationPath $installerZip -CompressionLevel Optimal
Write-Host "  Installer folder: $installerDir" -ForegroundColor Green
Write-Host "  Installer ZIP:    $installerZip" -ForegroundColor Green

# 4a. Build Total Commander native plugin ZIP (pluginst.inf at archive root)
Write-Host ""
Write-Host "--- Preparing Total Commander plugin ZIP ---" -ForegroundColor Cyan

if (Test-Path $tcInstallerDir) {
    Remove-PathSafe -PathToRemove $tcInstallerDir | Out-Null
}
New-Item -ItemType Directory -Path $tcInstallerDir | Out-Null
New-Item -ItemType Directory -Path (Join-Path $tcInstallerDir "64") | Out-Null

$pluginstInf = @"
[plugininstall]
description=Secure FTP plugin (x64) - static libssh2 build, no external SSH DLL required
type=wfx
file=sftpplug.wfx64
defaultdir=sftpplug
version=1.0 RC1
"@
Set-Content -Path (Join-Path $tcInstallerDir "pluginst.inf") -Value $pluginstInf -Encoding ASCII

$tcReadme = @"
Secure FTP plugin (x64 only)
Copyright (C) Marek Wesolowski

Help:
- Open sftpplug.chm for full documentation.
- You can also open help from the plugin connection dialog via the Help button.

Installation:
- Open this ZIP in Total Commander and press Enter on the archive.
- Confirm plugin installation when prompted.

Package contents:
- sftpplug.wfx64 (x64 plugin binary)
- sftp.php (current PHP Agent for modern environments)
- pluginst.inf (TC auto-install descriptor)
- readme.txt

Important:
- This package is x64-only.
- No external libssh2.dll is required in this package.
- Do not mix with old x86 package files.

Highlights:
- SFTP + SCP support
- Shell transfer fallback for restricted hosts
- Jump Host / ProxyJump for bastion-routed SSH sessions
- PHP Agent (HTTP) transfer mode for hosts without SSH account access
- PHP Agent script: sftp.php
- PHP Shell (HTTP) pseudo-terminal for remote command execution
- LAN Pair (SMB-like) for direct Windows-to-Windows local pairing
- PuTTY/WinSCP session import
- PPK/PEM key support
- Password manager integration (TC master password)
- More features are coming soon, including a planned SMB workflow for Windows-to-Windows scenarios.
"@
Set-Content -Path (Join-Path $tcInstallerDir "readme.txt") -Value $tcReadme -Encoding ASCII

Copy-Item -Path "$binDir\sftpplug.wfx64" -Destination (Join-Path $tcInstallerDir "sftpplug.wfx64") -Force
if (Test-Path "$binDir\sftp.php") {
    Copy-Item -Path "$binDir\sftp.php" -Destination (Join-Path $tcInstallerDir "sftp.php") -Force
}
if (Test-Path "$binDir\sftpplug.chm") {
    Copy-Item -Path "$binDir\sftpplug.chm" -Destination (Join-Path $tcInstallerDir "sftpplug.chm") -Force
}

if (Test-Path $tcInstallerZip) {
    Remove-Item $tcInstallerZip -Force
}
$sevenZip = Join-Path ${env:ProgramFiles} "7-Zip\7z.exe"
if (-not (Test-Path $sevenZip)) {
    $sevenZip = Join-Path ${env:ProgramFiles(x86)} "7-Zip\7z.exe"
}
if (Test-Path $sevenZip) {
    Push-Location $tcInstallerDir
    try {
        & $sevenZip a -tzip $tcInstallerZip * | Out-Null
    } finally {
        Pop-Location
    }
} else {
    Compress-Archive -Path (Join-Path $tcInstallerDir "*") -DestinationPath $tcInstallerZip -CompressionLevel Optimal
}
Write-Host "  TC ZIP:          $tcInstallerZip" -ForegroundColor Green

# 5. Cleanup intermediate files
Write-Host ""
Write-Host "--- Cleaning up intermediate files ---" -ForegroundColor Yellow

$cleanupTargets = @(
    (Join-Path $PSScriptRoot ".intermediates"),
    (Join-Path $PSScriptRoot ".vs"),
    (Join-Path $binDir "x64_Release")
)

foreach ($target in $cleanupTargets) {
    if (Test-Path $target) {
        if (Remove-PathSafe -PathToRemove $target) {
            Write-Host "  Removed: $target" -ForegroundColor Gray
        }
    }
}

# 6. Final summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "BUILD COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Final binaries in: $binDir" -ForegroundColor White
Write-Host "  - sftpplug.wfx64" -ForegroundColor Gray
Write-Host "  - sftp.php (current PHP Agent)" -ForegroundColor Gray
Write-Host "  - sftpplug.zip (Total Commander auto-install)" -ForegroundColor Gray
Write-Host "  - sftpplug-installer.zip" -ForegroundColor Gray
Write-Host "  - Auto-deploy target: $deployPluginDir" -ForegroundColor Gray
Write-Host ""
Write-Host "Installation:" -ForegroundColor Cyan
Write-Host "  Rozpakuj sftpplug-installer.zip i uruchom install_sftp_plugin.cmd" -ForegroundColor Gray
Write-Host ""
