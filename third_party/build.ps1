param(
    [switch]$argon,
    [switch]$libssh2,
    [switch]$x64only,
    [switch]$x86only
)

# Disable ANSI escape codes in PowerShell 7+ output
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText
}

# ============================================================================
# Configuration
# ============================================================================
$projectRoot  = $PSScriptRoot
$binDir       = Join-Path $projectRoot "bin"
$argonVcxproj = Join-Path $projectRoot "argon\vs2026\Argon2Static\Argon2Static.vcxproj"
$libssh2Src   = Join-Path $projectRoot "libssh2"

# Build both architectures unless restricted
$buildX64 = -not $x86only
$buildX86 = -not $x64only

# If no explicit target, build both
$buildArgon  = $argon  -or (-not $argon -and -not $libssh2)
$buildLibssh2 = $libssh2 -or (-not $argon -and -not $libssh2)

# ============================================================================
# Helper
# ============================================================================
function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "--- $msg ---" -ForegroundColor Cyan
}

function Write-Ok([string]$msg)  { Write-Host "  $msg" -ForegroundColor Green }
function Write-Err([string]$msg) { Write-Host "  $msg" -ForegroundColor Red }
function Write-Info([string]$msg){ Write-Host "  $msg" -ForegroundColor Gray }

function Assert-Exit([int]$code, [string]$label) {
    if ($code -ne 0) {
        Write-Err "$label FAILED (exit $code)"
        exit $code
    }
}

function Verify-MT([string]$libPath, [string]$label) {
    if (-not (Test-Path $libPath)) {
        Write-Err "$label — file not found: $libPath"
        return
    }
    $bytes = [System.IO.File]::ReadAllBytes($libPath)
    $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
    if ($text -match '/DEFAULTLIB:"LIBCMT"') {
        Write-Ok "$label — /MT (LIBCMT) OK"
    } elseif ($text -match '/DEFAULTLIB:"MSVCRT"') {
        Write-Err "$label — WARNING: still /MD (MSVCRT)!"
    } else {
        Write-Info "$label — no defaultlib directive (neutral)"
    }
}

# ============================================================================
# Step 1: Find MSBuild
# ============================================================================
Write-Step "Finding Visual Studio Build Tools"

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Write-Err "vswhere.exe not found."
    exit 1
}

$vsPath  = & $vswhere -latest -prerelease -requires Microsoft.Component.MSBuild -property installationPath
$msbuild = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"
Write-Info "MSBuild: $msbuild"

$vcToolsRoot    = Join-Path $vsPath "VC\Tools\MSVC"
$vcToolsVersion = Get-ChildItem $vcToolsRoot -Directory |
                  Sort-Object Name -Descending |
                  Select-Object -First 1 -ExpandProperty Name
Write-Info "VC Tools: $vcToolsVersion"

# ============================================================================
# Step 2: Find CMake (bundled with VS)
# ============================================================================
$cmake = Join-Path $vsPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if (-not (Test-Path $cmake)) {
    Write-Err "CMake not found in VS installation."
    exit 1
}
Write-Info "CMake: $cmake"

# ============================================================================
# Step 3: Prepare output dir
# ============================================================================
Write-Step "Preparing output directory"
New-Item -ItemType Directory -Path $binDir -Force | Out-Null
Write-Info "Output: $binDir"

# ============================================================================
# Step 4: Build Argon2
# ============================================================================
if ($buildArgon) {
    Write-Step "Building Argon2 static libraries"

    $argonBuildDir = Join-Path $projectRoot "argon\build"

    $platforms = @()
    if ($buildX64) { $platforms += @{ Name="x64";  MSBuild="x64";  Suffix="x64" } }
    if ($buildX86) { $platforms += @{ Name="Win32"; MSBuild="Win32"; Suffix="x86" } }

    foreach ($p in $platforms) {
        Write-Info "Argon2 $($p.Suffix)..."

        $args = @(
            $argonVcxproj,
            "/t:Rebuild",
            "/p:Configuration=ReleaseStatic",
            "/p:Platform=$($p.MSBuild)",
            "/p:PlatformToolset=v145",
            "/p:VCToolsVersion=$vcToolsVersion",
            "/p:WindowsTargetPlatformVersion=10.0",
            "/nologo", "/v:m", "/m"
        )

        & $msbuild @args
        Assert-Exit $LASTEXITCODE "Argon2 $($p.Suffix)"

        $src = Join-Path $argonBuildDir "$($p.Suffix)\argon2_a_$($p.Suffix).lib"
        $dst = Join-Path $binDir "argon2_a_$($p.Suffix).lib"
        Copy-Item $src $dst -Force
        Write-Ok "argon2_a_$($p.Suffix).lib copied"
        Verify-MT $dst "argon2_a_$($p.Suffix)"
    }

    # Clean argon build output (copied to bin, not needed in repo)
    $argonBld = Join-Path $projectRoot "argon\build"
    if (Test-Path $argonBld) {
        Remove-Item $argonBld -Recurse -Force -ErrorAction SilentlyContinue
        Write-Info "Argon2 build dir cleaned"
    }
}

# ============================================================================
# Step 5: Build libssh2
# ============================================================================
if ($buildLibssh2) {
    Write-Step "Building libssh2 static libraries"

    if (-not (Test-Path $libssh2Src)) {
        Write-Err "libssh2 source not found: $libssh2Src"
        exit 1
    }

    $env:CLICOLOR_FORCE         = "0"
    $env:NO_COLOR               = "1"
    $env:MSBUILDTERMINALLOGGER  = "off"

    $cmakeBase = @(
        "-DCRYPTO_BACKEND=WinCNG",
        "-DBUILD_SHARED_LIBS=OFF",
        "-DBUILD_TESTING=OFF",
        "-DBUILD_EXAMPLES=OFF",
        "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded",
        "-DCMAKE_POLICY_DEFAULT_CMP0091=NEW",
        "-DCMAKE_COLOR_DIAGNOSTICS=OFF",
        "-T", "v145"
    )

    $platforms = @()
    if ($buildX64) { $platforms += @{ CMakeArch="x64";  Suffix="x64" } }
    if ($buildX86) { $platforms += @{ CMakeArch="Win32"; Suffix="x86" } }

    foreach ($p in $platforms) {
        Write-Info "libssh2 $($p.Suffix)..."

        $bldDir = Join-Path $libssh2Src "bld_$($p.Suffix)"

        # Clean previous cmake build
        if (Test-Path $bldDir) {
            Remove-Item $bldDir -Recurse -Force -ErrorAction SilentlyContinue
        }

        $tmpOut = [System.IO.Path]::GetTempFileName()
        $tmpErr = [System.IO.Path]::GetTempFileName()

        # Configure
        $proc = Start-Process $cmake `
            -ArgumentList (@("-B", $bldDir, "-A", $p.CMakeArch) + $cmakeBase + @($libssh2Src)) `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr
        Get-Content $tmpOut, $tmpErr | Where-Object { $_ -notmatch "^--" -and $_.Trim() -ne "" } |
            ForEach-Object { Write-Info $_ }
        Assert-Exit $proc.ExitCode "libssh2 $($p.Suffix) cmake configure"

        # Build
        $proc = Start-Process $cmake `
            -ArgumentList ("--build", $bldDir, "--config", "Release") `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr
        Get-Content $tmpOut, $tmpErr | Where-Object { $_.Trim() -ne "" } |
            ForEach-Object { Write-Info $_ }
        Assert-Exit $proc.ExitCode "libssh2 $($p.Suffix) cmake build"

        Remove-Item $tmpOut, $tmpErr -Force -ErrorAction SilentlyContinue

        # Copy
        $src = Join-Path $bldDir "src\Release\libssh2.lib"
        $dst = Join-Path $binDir "libssh2_$($p.Suffix).lib"
        Copy-Item $src $dst -Force
        Write-Ok "libssh2_$($p.Suffix).lib copied"
        Verify-MT $dst "libssh2_$($p.Suffix)"

        # Clean cmake build dir
        Remove-Item $bldDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Info "libssh2 $($p.Suffix) build dir cleaned"
    }
}

# ============================================================================
# Summary
# ============================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "DEPENDENCIES BUILD COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output: $binDir" -ForegroundColor White
Get-ChildItem $binDir -Filter "*.lib" | ForEach-Object {
    $kb = [math]::Round($_.Length / 1KB)
    Write-Host "  $($_.Name)  ($kb KB)" -ForegroundColor Gray
}
Write-Host ""
