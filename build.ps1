param(
    [switch]$en,
    [switch]$pl,
    [switch]$de,
    [switch]$fr,
    [switch]$es,
    [switch]$ru,
    [switch]$chm,
    [switch]$nochm,
    [switch]$nodeploy,
    [switch]$nozip
)

# ============================================================================
# Configuration
# ============================================================================
$projectName = "SFTPplug"
$projectRoot = $PSScriptRoot
$binDir = Join-Path $projectRoot "bin"
$buildDir = Join-Path $projectRoot "build"
$buildOutputDir    = Join-Path $buildDir "bin\x64_Release"
$buildOutputDirX86 = Join-Path $buildDir "bin\Win32_Release"
$phpAgentSource = Join-Path $projectRoot "src\agent\sftp.php"
$helpProject = Join-Path $projectRoot "src\help\sftpplug.hhp"
$helpCompiled = Join-Path $projectRoot "src\help\sftpplug.chm"

# ============================================================================
# Helper Functions
# ============================================================================

function Get-TotalCommanderPath {
    <#
    .SYNOPSIS
    Finds Total Commander installation path from registry or default locations.
    #>
    
    # Try HKEY_CURRENT_USER first
    $tcPath = $null
    try {
        $tcKey = Get-ItemProperty -Path "HKCU:\Software\Ghisler\Total Commander" -ErrorAction SilentlyContinue
        if ($tcKey -and $tcKey.InstallDir) {
            $tcPath = $tcKey.InstallDir
            Write-Host "  Found TC in HKCU: $tcPath" -ForegroundColor Gray
        }
    } catch {
        # Ignore
    }
    
    # Try HKEY_LOCAL_MACHINE if not found in HKCU
    if (-not $tcPath) {
        try {
            $tcKey = Get-ItemProperty -Path "HKLM:\Software\Ghisler\Total Commander" -ErrorAction SilentlyContinue
            if ($tcKey -and $tcKey.InstallDir) {
                $tcPath = $tcKey.InstallDir
                Write-Host "  Found TC in HKLM: $tcPath" -ForegroundColor Gray
            }
        } catch {
            # Ignore
        }
    }
    
    # Fallback to default locations
    if (-not $tcPath) {
        $defaultPaths = @(
            "C:\totalcmd",
            "${env:ProgramFiles}\totalcmd",
            "${env:ProgramFiles(x86)}\totalcmd"
        )
        foreach ($path in $defaultPaths) {
            if (Test-Path (Join-Path $path "TOTALCMD64.EXE")) {
                $tcPath = $path
                Write-Host "  Found TC in default location: $tcPath" -ForegroundColor Gray
                break
            }
        }
    }
    
    return $tcPath
}

function Stop-TotalCommander {
    <#
    .SYNOPSIS
    Stops all running Total Commander processes.
    #>
    Write-Host "  Checking for running Total Commander instances..." -ForegroundColor Gray
    
    $tcProcesses = Get-Process -Name "TOTALCMD*", "TOTALCMD64" -ErrorAction SilentlyContinue
    if ($tcProcesses) {
        Write-Host "  Stopping $($tcProcesses.Count) Total Commander process(es)..." -ForegroundColor Yellow
        foreach ($proc in $tcProcesses) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-Host "    Stopped: $($proc.Name) (PID: $($proc.Id))" -ForegroundColor Gray
            } catch {
                Write-Host "    Failed to stop $($proc.Name): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        Start-Sleep -Milliseconds 500  # Wait for processes to fully terminate
    } else {
        Write-Host "  No running Total Commander instances found" -ForegroundColor Gray
    }
}

function Select-ResourceLanguage {
    param(
        [Parameter(Mandatory = $true)][string]$LanguageCode
    )
    
    $resourceScriptPath = Join-Path $projectRoot "src\res\sftpplug.rc"
    $preserveDir = Join-Path $projectRoot ".preserve"
    $resourceScriptBackup = Join-Path $preserveDir "sftpplug.rc.original"
    
    if ($LanguageCode -eq "all") {
        return
    }
    
    if (-not (Test-Path $resourceScriptPath)) {
        throw "Resource script not found: $resourceScriptPath"
    }
    
    # Create preserve directory
    New-Item -ItemType Directory -Path $preserveDir -Force | Out-Null
    
    # Backup original RC file
    Copy-Item -Path $resourceScriptPath -Destination $resourceScriptBackup -Force
    
    # UTF-8 without BOM — required for Cyrillic and other non-Latin scripts.
    # CP1250 (old default) silently corrupted any character outside Latin/CE range.
    $rcEncoding = New-Object System.Text.UTF8Encoding($false)
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
        ru = @{
            marker  = "// Russian resources"
            pattern = "(?s)\r?\n?/////////////////////////////////////////////////////////////////////////////\r?\n// Russian resources.*?#endif\s*// Russian resources\r?\n?"
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
    
    # Remove all other language sections
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
    
    # For non-EN builds, ensure icons are present
    if ($LanguageCode -ne "en") {
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
    
    # Write modified RC file
    [System.IO.File]::WriteAllText($resourceScriptPath, $content, $rcEncoding)
    Write-Host "  Applied resource language filter: $LanguageCode" -ForegroundColor Gray
}

function Restore-ResourceLanguage {
    $preserveDir = Join-Path $projectRoot ".preserve"
    $resourceScriptBackup = Join-Path $preserveDir "sftpplug.rc.original"
    
    if (Test-Path $resourceScriptBackup) {
        $resourceScriptPath = Join-Path $projectRoot "src\res\sftpplug.rc"
        Copy-Item -Path $resourceScriptBackup -Destination $resourceScriptPath -Force
        Remove-Item $resourceScriptBackup -Force -ErrorAction SilentlyContinue
        Remove-Item $preserveDir -Force -ErrorAction SilentlyContinue
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

function Compile-CHM {
    <#
    .SYNOPSIS
    Compiles the CHM help file using HTML Help Workshop.
    #>
    Write-Host ""
    Write-Host "--- Compiling CHM Help ---" -ForegroundColor Cyan
    
    $hhcPaths = @(
        (Join-Path ${env:ProgramFiles(x86)} "HTML Help Workshop\hhc.exe"),
        (Join-Path $env:ProgramFiles "HTML Help Workshop\hhc.exe")
    )
    
    $hhcExe = $null
    foreach ($path in $hhcPaths) {
        if (Test-Path $path) {
            $hhcExe = $path
            break
        }
    }
    
    if (-not $hhcExe) {
        Write-Host "  HTML Help Workshop not found - CHM compilation skipped" -ForegroundColor Yellow
        Write-Host "  Download from: https://www.microsoft.com/en-us/download/details.aspx?id=21138" -ForegroundColor Gray
        return $false
    }
    
    if (-not (Test-Path $helpProject)) {
        Write-Host "  Help project not found: $helpProject" -ForegroundColor Yellow
        return $false
    }
    
    # Remove old compiled CHM
    if (Test-Path $helpCompiled) {
        Remove-Item $helpCompiled -Force -ErrorAction SilentlyContinue
    }
    
    # Compile CHM
    Push-Location (Split-Path $helpProject)
    try {
        Write-Host "  Compiling: $helpProject" -ForegroundColor Gray
        $output = & $hhcExe $helpProject 2>&1
        # hhc.exe always returns exit code 1, even on success.
        # Determine success by checking whether the output .chm was created.
        if (Test-Path $helpCompiled) {
            Write-Host "  CHM compiled successfully" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  CHM compilation failed (output file not created)" -ForegroundColor Red
            if ($output) {
                Write-Host "  $output" -ForegroundColor DarkGray
            }
            return $false
        }
    } finally {
        Pop-Location
    }
}

function Clean-BuildOutput {
    <#
    .SYNOPSIS
    Removes all intermediate build files, leaving only the final wfx.
    #>
    Write-Host "  Cleaning intermediate files..." -ForegroundColor Gray
    
    foreach ($outDir in @($buildOutputDir, $buildOutputDirX86)) {
        if (Test-Path $outDir) {
            Get-ChildItem -Path $outDir | Where-Object {
                $_.Name -notlike "*.wfx"
            } | Remove-Item -Recurse -Force
        }
    }
    $intermediatesDir = Join-Path $buildDir ".intermediates"
    if (Test-Path $intermediatesDir) {
        Remove-Item $intermediatesDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# Main Build Script
# ============================================================================

# Determine build language
$buildLanguage = "all"
$selectedLanguageFlags = @()
if ($en) { $selectedLanguageFlags += "en" }
if ($pl) { $selectedLanguageFlags += "pl" }
if ($de) { $selectedLanguageFlags += "de" }
if ($fr) { $selectedLanguageFlags += "fr" }
if ($es) { $selectedLanguageFlags += "es" }
if ($ru) { $selectedLanguageFlags += "ru" }

if ($selectedLanguageFlags.Count -gt 1) {
    Write-Error "Use only one language switch: -en, -pl, -de, -fr, -es or -ru."
    exit 1
}
if ($selectedLanguageFlags.Count -eq 1) {
    $buildLanguage = $selectedLanguageFlags[0]
}

# RU + nochm → bin_ru, no deploy, no kill TC
if ($ru -and $nochm) {
    $binDir = Join-Path $projectRoot "bin_ru"
    $nodeploy = $true
}

# Determine CHM build mode
$buildCHM = (-not $nochm) -or $chm

Write-Host "--- SFTP Plugin Build Script ---" -ForegroundColor Cyan
Write-Host "Project Root: $projectRoot" -ForegroundColor Gray
Write-Host "Resource Language: $buildLanguage" -ForegroundColor Gray
Write-Host "Build CHM: $($(if ($buildCHM) { 'Yes' } else { 'No' }))" -ForegroundColor Gray
Write-Host ""

# ============================================================================
# Step 1: Find MSBuild
# ============================================================================
Write-Host "--- Finding Visual Studio Build Tools ---" -ForegroundColor Cyan

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Write-Error "vswhere.exe not found. Install Visual Studio 2022 or later."
    exit 1
}

$vsPath = &$vswhere -latest -prerelease -requires Microsoft.Component.MSBuild -property installationPath
if (-not $vsPath) {
    Write-Error "Visual Studio Build Tools not found."
    exit 1
}

$msbuild = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"
$vcToolsRoot = Join-Path $vsPath "VC\Tools\MSVC"

Write-Host "  MSBuild: $msbuild" -ForegroundColor Gray

# Get VC tools version
$vcToolsVersion = $null
if (Test-Path $vcToolsRoot) {
    $vcToolsVersion = Get-ChildItem $vcToolsRoot -Directory |
        Sort-Object Name -Descending |
        Select-Object -First 1 -ExpandProperty Name
    Write-Host "  VC Tools Version: $vcToolsVersion" -ForegroundColor Gray
}

# Validate VC tools version
if ($vcToolsVersion) {
    $minimumVcToolsVersion = [version]"14.50.0.0"
    $currentVcToolsVersion = [version]("$vcToolsVersion.0")
    if ($currentVcToolsVersion -lt $minimumVcToolsVersion) {
        Write-Error "VC tools $vcToolsVersion detected. Version 14.50 or later required."
        exit 1
    }
}

# ============================================================================
# Step 2: Prepare directories
# ============================================================================
Write-Host ""
Write-Host "--- Preparing Build Directories ---" -ForegroundColor Cyan

# Clean bin directory (only final output)
if (-not (Remove-PathSafe -PathToRemove $binDir)) {
    Write-Host "  Continuing with existing bin directory" -ForegroundColor Yellow
}
New-Item -ItemType Directory -Path $binDir -Force | Out-Null

# Clean build output directory
if (-not (Remove-PathSafe -PathToRemove $buildOutputDir)) {
    Write-Host "  Continuing with existing build output" -ForegroundColor Yellow
}

Write-Host "  Directories ready" -ForegroundColor Gray

# ============================================================================
# Step 3: Build
# ============================================================================
$vcxprojPath = Join-Path $buildDir "SFTPplug.vcxproj"
if (-not (Test-Path $vcxprojPath)) {
    Write-Error "Project file not found: $vcxprojPath"
    exit 1
}

$msBuildBase = @(
    $vcxprojPath,
    "/t:Rebuild",
    "/p:Configuration=Release",
    "/p:PlatformToolset=v145",
    "/p:WindowsTargetPlatformVersion=10.0",
    "/p:DebugSymbols=false",
    "/p:DebugType=none",
    "/m",
    "/nologo",
    "/v:m"
)
if ($vcToolsVersion) { $msBuildBase += "/p:VCToolsVersion=$vcToolsVersion" }

# --- x64 ---
Write-Host ""
Write-Host "--- Building Release x64 ---" -ForegroundColor Cyan

Select-ResourceLanguage -LanguageCode $buildLanguage
$msbuildExitCode = 0
try {
    Write-Host "  Building: $vcxprojPath (x64)" -ForegroundColor Gray
    &$msbuild ($msBuildBase + @("/p:Platform=x64"))
    $msbuildExitCode = $LASTEXITCODE
} finally {
    Restore-ResourceLanguage
}
if ($msbuildExitCode -ne 0) {
    Write-Host "!!! BUILD FAILED (x64) !!!" -ForegroundColor Red
    exit $msbuildExitCode
}
Write-Host "  x64 build completed" -ForegroundColor Green

# --- x86 ---
Write-Host ""
Write-Host "--- Building Release x86 ---" -ForegroundColor Cyan

Select-ResourceLanguage -LanguageCode $buildLanguage
$msbuildExitCode = 0
try {
    Write-Host "  Building: $vcxprojPath (x86)" -ForegroundColor Gray
    &$msbuild ($msBuildBase + @("/p:Platform=Win32"))
    $msbuildExitCode = $LASTEXITCODE
} finally {
    Restore-ResourceLanguage
}
if ($msbuildExitCode -ne 0) {
    Write-Host "!!! BUILD FAILED (x86) !!!" -ForegroundColor Red
    exit $msbuildExitCode
}
Write-Host "  x86 build completed" -ForegroundColor Green

# Clean intermediate files
Clean-BuildOutput

# ============================================================================
# Step 4: Compile CHM (if requested)
# ============================================================================
if ($buildCHM) {
    Compile-CHM | Out-Null
}

# ============================================================================
# Step 5: Create ZIP package (ONLY output in bin\)
# ============================================================================
if (-not $nozip) {
    Write-Host ""
    Write-Host "--- Creating ZIP Package ---" -ForegroundColor Cyan
    
    $zipPath = Join-Path $binDir "$projectName.zip"
    $pluginstInf = @"
[plugininstall]
description=Secure FTP plugin (x64+x86) - static build, no external DLL required
type=wfx
file=$projectName.wfx
file64=$projectName.wfx64
defaultdir=$projectName
version=1.0
"@

    Add-Type -AssemblyName System.IO.Compression

    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

    $outStream = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::Create)
    $zip = [System.IO.Compression.ZipArchive]::new($outStream, [System.IO.Compression.ZipArchiveMode]::Create)

    function Add-ZipFile([string]$src, [string]$entryName) {
        $entry = $zip.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
        $dst = $entry.Open()
        $fs  = [System.IO.File]::OpenRead($src)
        try   { $fs.CopyTo($dst) }
        finally { $fs.Dispose(); $dst.Dispose() }
    }

    function Add-ZipString([string]$text, [string]$entryName) {
        $entry = $zip.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
        $dst = $entry.Open()
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($text)
        try   { $dst.Write($bytes, 0, $bytes.Length) }
        finally { $dst.Dispose() }
    }

    try {
        Add-ZipFile  (Join-Path $buildOutputDir    "$projectName.wfx") "$projectName.wfx64"
        Add-ZipFile  (Join-Path $buildOutputDirX86 "$projectName.wfx") "$projectName.wfx"
        Add-ZipString $pluginstInf "pluginst.inf"

        if (Test-Path $phpAgentSource) { Add-ZipFile $phpAgentSource "sftp.php" }
        if (Test-Path $helpCompiled)   { Add-ZipFile $helpCompiled   "$projectName.chm" }

        $readmeSource = Join-Path $projectRoot "src\help\readme.txt"
        if (Test-Path $readmeSource)   { Add-ZipFile $readmeSource   "readme.txt" }

        # Set a future timestamp on the ZIP — signature of a static, dependency-free build
        $futureDate = [DateTime]"2030-01-01 00:00:00"
        (Get-Item $zipPath).LastWriteTime   = $futureDate
        (Get-Item $zipPath).CreationTime    = $futureDate
        (Get-Item $zipPath).LastAccessTime  = $futureDate
        Write-Host "  Created: $projectName.zip (dated $($futureDate.ToString('yyyy-MM-dd')))" -ForegroundColor Green
    } catch {
        Write-Host "  Failed to create ZIP: $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        $zip.Dispose()
        $outStream.Dispose()
    }
}

# ============================================================================
# Step 6: Deploy to Total Commander
# ============================================================================
$deploySuccess = $false
if (-not $nodeploy) {
    Write-Host ""
    Write-Host "--- Deploying to Total Commander ---" -ForegroundColor Cyan
    
    $tcPath = Get-TotalCommanderPath
    
    if ($tcPath) {
        # Stop Total Commander
        Stop-TotalCommander
        
        # Deploy files
        $pluginDir = Join-Path $tcPath "plugins\wfx\$projectName"
        try {
            New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
            
            Copy-Item -Path (Join-Path $buildOutputDir    "$projectName.wfx") -Destination (Join-Path $pluginDir "$projectName.wfx64") -Force
            Write-Host "  Deployed: $projectName.wfx64" -ForegroundColor Green
            Copy-Item -Path (Join-Path $buildOutputDirX86 "$projectName.wfx") -Destination (Join-Path $pluginDir "$projectName.wfx") -Force
            Write-Host "  Deployed: $projectName.wfx (x86)" -ForegroundColor Green
            
            if (Test-Path $helpCompiled) {
                Copy-Item -Path $helpCompiled -Destination (Join-Path $pluginDir "$projectName.chm") -Force
                Write-Host "  Deployed: $projectName.chm" -ForegroundColor Green
            }
            
            if (Test-Path $phpAgentSource) {
                Copy-Item -Path $phpAgentSource -Destination (Join-Path $pluginDir "sftp.php") -Force
                Write-Host "  Deployed: sftp.php" -ForegroundColor Green
            }
            
            $deploySuccess = $true
        } catch {
            Write-Host "  Deploy failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "  Total Commander not found - skipping deploy" -ForegroundColor Yellow
        Write-Host "  Install TC or set registry key: HKCU\Software\Ghisler\Total Commander\InstallDir" -ForegroundColor Gray
    }
}

# ============================================================================
# Step 7: Clean up intermediate build directory
# ============================================================================
$buildBinDir = Join-Path $buildDir "bin"
if (Test-Path $buildBinDir) {
    Remove-Item $buildBinDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ============================================================================
# Step 8: Final Summary
# ============================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "BUILD COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output directory: $binDir" -ForegroundColor White
if (Test-Path (Join-Path $binDir "$projectName.zip")) {
    Write-Host "  - $projectName.zip (TC auto-install)" -ForegroundColor Gray
}

if ($deploySuccess) {
    Write-Host ""
    Write-Host "Deployed to: $tcPath\plugins\wfx\$projectName" -ForegroundColor Green
    Write-Host ""
    Write-Host "Restart Total Commander to load the plugin." -ForegroundColor Cyan
}

Write-Host ""
