#requires -Version 5.1
<#
.SYNOPSIS
Builds the static crypto stack (OpenSSL libcrypto and libssh2) for SFTPplug.

.DESCRIPTION
Produces DLL-free /MT static libraries in src\lib and the libssh2 public
headers in src\include\libssh2.

Provenance:
  OpenSSL  release tarball; SHA-256 pinned below and the detached PGP
           signature verified against the release key kept in
           thirdparty\keys (primary-key fingerprint pinned below).
  libssh2  git submodule on the libssh2-1.11.1 tag, plus the patch series in
           thirdparty\patches\libssh2-1.11.1 (Debian security backports and
           SFTPplug's own changes).

The toolchain is detected on evidence by tools\Toolchain.psm1. x64 and x86
build in parallel, each in its own developer shell.

.PARAMETER Arch
x64, x86 or both (default).

.PARAMETER SkipOpenSSL
Reuse the OpenSSL already installed under thirdparty\build.

.PARAMETER Clean
Delete thirdparty\build before building.

.PARAMETER NoSignatureCheck
Skip the PGP check when gpg is unavailable. The SHA-256 pin still applies.
#>
param(
    [ValidateSet('x64', 'x86', 'both')] [string]$Arch = 'both',
    [switch]$SkipOpenSSL,
    [switch]$Clean,
    [switch]$NoSignatureCheck
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
Import-Module (Join-Path $PSScriptRoot 'tools\Toolchain.psm1') -Force

# ============================================================================
# Pins
# ============================================================================
$OpenSslVersion     = '4.1.0'
$OpenSslSha256      = '50c17baf54cb008f6ce42d50deb4b28050a1aad711636cabd4b241c7e90cc2fd'
$OpenSslSigningKey  = 'B146647E45A7B33947AB226B2A2C87D161692D40'
$OpenSslUrl         = "https://github.com/openssl/openssl/releases/download/openssl-$OpenSslVersion/openssl-$OpenSslVersion.tar.gz"
$Libssh2Tag         = 'libssh2-1.11.1'

# Only what SSH negotiates survives. Kept: AES (CBC/CTR/GCM), ChaCha20-Poly1305,
# SHA-1/SHA-2, MD5 (legacy fingerprints), HMAC, RSA, prime-field EC (ECDSA,
# ECDH), Ed25519, X25519, DH, 3DES, and Argon2 with BLAKE2 for PuTTY v3 keys.
# libssh2 reads the resulting OPENSSL_NO_* macros and drops the matching
# algorithms itself.
#
# no-autoload-config: a static library would otherwise read openssl.cnf from
# the OPENSSLDIR compiled in at build time - a path that does not exist on a
# user's machine and could be created by anyone (config-planting).
$OpenSslOptions = @(
    'no-shared', 'no-module', 'no-dso', 'no-autoload-config', 'no-tests', 'no-apps', 'no-docs',
    'no-deprecated', 'no-legacy', 'no-tls', 'no-dtls', 'no-quic',
    'no-aria', 'no-async', 'no-bf', 'no-camellia',
    'no-cast', 'no-cmp', 'no-cms', 'no-comp', 'no-ct', 'no-dgram',
    'no-dsa', 'no-ec2m', 'no-gost', 'no-idea', 'no-md4', 'no-mdc2', 'no-ml-dsa',
    'no-ml-kem', 'no-multiblock', 'no-nextprotoneg', 'no-ocb', 'no-ocsp',
    'no-psk', 'no-rc2', 'no-rc4', 'no-rfc3779', 'no-rmd160',
    'no-seed', 'no-siv', 'no-slh-dsa', 'no-sm2', 'no-sm3', 'no-sm4', 'no-srp',
    'no-srtp', 'no-ssl-trace', 'no-ts', 'no-ui-console', 'no-whirlpool',
    'no-winstore', 'no-zlib', 'no-zstd'
)
# Control Flow Guard in every object that ends up in the plugin; /Brepro keeps
# the libraries byte-reproducible for a given toolchain.
$DependencyCFlags = '/guard:cf /Brepro'

# ============================================================================
# Layout
# ============================================================================
$Root        = $PSScriptRoot
$ThirdParty  = Join-Path $Root 'thirdparty'
$Downloads   = Join-Path $ThirdParty 'downloads'
$OpenSslSrc  = Join-Path $ThirdParty 'openssl'
$Libssh2Src  = Join-Path $ThirdParty 'libssh2'
$PatchRoot   = Join-Path $ThirdParty 'patches'
$KeyFile     = Join-Path $ThirdParty "keys\openssl-release-$OpenSslSigningKey.asc"
$BuildRoot   = Join-Path $ThirdParty 'build'
$LogRoot     = Join-Path $BuildRoot 'logs'
$LibDest     = Join-Path $Root 'src\lib'
$HeaderDest  = Join-Path $Root 'src\include\libssh2'
$Manifest    = Join-Path $LibDest 'deps-manifest.json'

$Archs = if ($Arch -eq 'both') { @('x64', 'x86') } else { @($Arch) }

function Write-Section([string]$Title) { Write-Host ''; Write-Host "=== $Title ===" -ForegroundColor Cyan }
function Write-Step([string]$Text)     { Write-Host "  $Text" -ForegroundColor Gray }
function Write-Ok([string]$Text)       { Write-Host "  $Text" -ForegroundColor Green }

function Get-Sha256([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }

function Invoke-Native {
    param([Parameter(Mandatory)] [string]$Exe, [string[]]$Arguments = @(), [switch]$Quiet)
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($Quiet) { $out = & $Exe @Arguments 2>&1 } else { & $Exe @Arguments 2>&1 | Out-Host; $out = $null }
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $out }
    } finally { $ErrorActionPreference = $saved }
}

# ============================================================================
# Tools
# ============================================================================
Write-Section 'Toolchain'
$Toolchain = Get-SftpToolchain -Arch $Archs
Write-SftpToolchainSummary $Toolchain

$Perl = Find-SftpBuildTool -Name 'Perl' -Executable 'perl.exe' -Candidates @(
    'C:\Strawberry\perl\bin\perl.exe',
    (Join-Path $env:ProgramFiles 'Strawberry\perl\bin\perl.exe')
) -Validate {
    param($p)
    # OpenSSL's VC build needs a native Perl with the CORE modules Configure
    # uses; Git for Windows ships an MSYS Perl that fails both checks.
    $r = Invoke-Native -Exe $p -Arguments @('-MIPC::Cmd', '-MParams::Check', '-e', 'print $^O') -Quiet
    $r.ExitCode -eq 0 -and "$($r.Output)".Trim() -eq 'MSWin32'
}
if (-not $Perl) { throw 'Native Perl (Strawberry) not found. Install it, or set Perl in build.local.psd1.' }

$Nasm = Find-SftpBuildTool -Name 'Nasm' -Executable 'nasm.exe' -Candidates @(
    (Join-Path $env:ProgramFiles 'NASM\nasm.exe'),
    (Join-Path $env:LOCALAPPDATA 'bin\NASM\nasm.exe')
)
if (-not $Nasm) { throw 'NASM not found (OpenSSL assembly needs it). Install it, or set Nasm in build.local.psd1.' }

$CMake = Find-SftpBuildTool -Name 'CMake' -Executable 'cmake.exe' -Candidates @(
    (Join-Path $Toolchain.VsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'),
    (Join-Path $env:ProgramFiles 'CMake\bin\cmake.exe')
)
if (-not $CMake) { throw 'CMake not found. Install it (or the VS "C++ CMake tools" component), or set CMake in build.local.psd1.' }

$Jom = Find-SftpBuildTool -Name 'Jom' -Executable 'jom.exe'
$Gpg = Find-SftpBuildTool -Name 'Gpg' -Executable 'gpg.exe' -Candidates @(
    (Join-Path ${env:ProgramFiles(x86)} 'GnuPG\bin\gpg.exe'),
    (Join-Path $env:ProgramFiles 'GnuPG\bin\gpg.exe'),
    (Join-Path $env:ProgramFiles 'Git\usr\bin\gpg.exe')
)
$Git = Find-SftpBuildTool -Name 'Git' -Executable 'git.exe'
if (-not $Git) { throw 'git not found.' }

Write-Step "perl  : $Perl"
Write-Step "nasm  : $Nasm"
Write-Step "cmake : $CMake"
Write-Step "jom   : $(if ($Jom) { $Jom } else { 'not found - nmake (x64 and x86 still build in parallel)' })"
Write-Step "gpg   : $(if ($Gpg) { $Gpg } else { 'not found' })"

# ============================================================================
# Sources
# ============================================================================
function Assert-SubmoduleTag([string]$Path, [string]$Tag) {
    if (-not (Test-Path -LiteralPath (Join-Path $Path '.git'))) {
        throw "Submodule $Path is not initialised. Run: git submodule update --init"
    }
    $r = Invoke-Native -Exe $Git -Arguments @('-C', $Path, 'describe', '--tags', '--exact-match', 'HEAD') -Quiet
    $actual = "$($r.Output)".Trim()
    if ($r.ExitCode -ne 0 -or $actual -ne $Tag) { throw "$Path is at '$actual', expected tag $Tag." }
    Write-Step "$((Split-Path $Path -Leaf)) @ $Tag"
}

function Invoke-PatchSeries([string]$Path, [string]$Tag) {
    # Applies thirdparty\patches\<tag>\series as one unit. A reverse check tells
    # an already patched tree from a pristine one; anything else is refused.
    $dir = Join-Path $PatchRoot $Tag
    $series = Join-Path $dir 'series'
    if (-not (Test-Path -LiteralPath $series)) { Write-Step "no patches for $Tag"; return @() }
    $patches = @(Get-Content -LiteralPath $series | ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object { Join-Path $dir $_ })
    if ($patches.Count -eq 0) { return @() }
    $reverse = @($patches[($patches.Count - 1)..0])

    if ((Invoke-Native -Exe $Git -Arguments (@('-C', $Path, 'apply', '--check') + $patches) -Quiet).ExitCode -eq 0) {
        if ((Invoke-Native -Exe $Git -Arguments (@('-C', $Path, 'apply') + $patches)).ExitCode -ne 0) { throw "git apply failed in $Path" }
        Write-Ok "applied $($patches.Count) patches to $(Split-Path $Path -Leaf)"
    } elseif ((Invoke-Native -Exe $Git -Arguments (@('-C', $Path, 'apply', '--reverse', '--check') + $reverse) -Quiet).ExitCode -eq 0) {
        Write-Step "$($patches.Count) patches already applied to $(Split-Path $Path -Leaf)"
    } else {
        throw "$Path is neither pristine $Tag nor patched with its series. Inspect: git -C $Path status"
    }
    return $patches
}

function Get-OpenSslSource {
    if (-not (Test-Path -LiteralPath $Downloads)) { New-Item -ItemType Directory -Path $Downloads -Force | Out-Null }
    $tarball = Join-Path $Downloads "openssl-$OpenSslVersion.tar.gz"
    $signature = "$tarball.asc"
    $stamp = Join-Path $OpenSslSrc '.sftpplug-source'

    if ((Test-Path -LiteralPath $stamp) -and ((Get-Content -LiteralPath $stamp -Raw).Trim() -eq $OpenSslSha256)) {
        Write-Step "OpenSSL $OpenSslVersion source already extracted and verified"
        return
    }

    foreach ($pair in @(@($tarball, $OpenSslUrl), @($signature, "$OpenSslUrl.asc"))) {
        if (-not (Test-Path -LiteralPath $pair[0])) {
            Write-Step "downloading $($pair[1])"
            Invoke-WebRequest -Uri $pair[1] -OutFile $pair[0] -UseBasicParsing
        }
    }

    $actual = Get-Sha256 $tarball
    if ($actual -ne $OpenSslSha256) {
        Remove-Item -LiteralPath $tarball -Force
        throw "OpenSSL tarball SHA-256 mismatch: expected $OpenSslSha256, got $actual (file removed)."
    }
    Write-Ok "SHA-256 matches pin $OpenSslSha256"

    if ($Gpg) {
        # Isolated keyring holding only the pinned release key: a signature is
        # accepted only if VALIDSIG names exactly that primary key.
        $gnupgHome = Join-Path $Downloads 'gnupg'
        if (Test-Path -LiteralPath $gnupgHome) { Remove-Item -LiteralPath $gnupgHome -Recurse -Force }
        New-Item -ItemType Directory -Path $gnupgHome -Force | Out-Null
        $savedHome = $env:GNUPGHOME
        $env:GNUPGHOME = $gnupgHome
        try {
            if ((Invoke-Native -Exe $Gpg -Arguments @('--batch', '--quiet', '--import', $KeyFile) -Quiet).ExitCode -ne 0) {
                throw "gpg could not import $KeyFile"
            }
            $r = Invoke-Native -Exe $Gpg -Arguments @('--batch', '--status-fd', '1', '--verify', $signature, $tarball) -Quiet
            $validSig = @($r.Output | Where-Object { "$_" -match '^\[GNUPG:\] VALIDSIG ' }) | Select-Object -First 1
            $primary = if ($validSig) { ("$validSig" -split '\s+')[-1] } else { '' }
            if ($r.ExitCode -ne 0 -or $primary -ne $OpenSslSigningKey) {
                throw "OpenSSL signature check failed (primary key '$primary', expected $OpenSslSigningKey)."
            }
            Write-Ok "PGP signature valid, primary key $OpenSslSigningKey"
        } finally {
            $gpgconf = Join-Path (Split-Path -Parent $Gpg) 'gpgconf.exe'
            if (Test-Path -LiteralPath $gpgconf) { Invoke-Native -Exe $gpgconf -Arguments @('--kill', 'gpg-agent') -Quiet | Out-Null }
            $env:GNUPGHOME = $savedHome
            Remove-Item -LiteralPath $gnupgHome -Recurse -Force -ErrorAction SilentlyContinue
        }
    } elseif (-not $NoSignatureCheck) {
        throw 'gpg not found; install GnuPG (Git for Windows ships one) or pass -NoSignatureCheck to rely on the SHA-256 pin alone.'
    } else {
        Write-Host '  WARNING: PGP signature not checked (-NoSignatureCheck); SHA-256 pin enforced' -ForegroundColor Yellow
    }

    if (Test-Path -LiteralPath $OpenSslSrc) { Remove-Item -LiteralPath $OpenSslSrc -Recurse -Force }
    $staging = Join-Path $ThirdParty "openssl-$OpenSslVersion"
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    $tar = Join-Path $env:SystemRoot 'System32\tar.exe'
    if ((Invoke-Native -Exe $tar -Arguments @('-xzf', $tarball, '-C', $ThirdParty) -Quiet).ExitCode -ne 0) { throw 'tar extraction failed' }
    Rename-Item -LiteralPath $staging -NewName (Split-Path $OpenSslSrc -Leaf)
    Set-Content -LiteralPath $stamp -Value $OpenSslSha256 -Encoding Ascii
    Write-Ok "OpenSSL $OpenSslVersion extracted to thirdparty\openssl"
}

Write-Section 'Sources'
Assert-SubmoduleTag $Libssh2Src $Libssh2Tag
$AppliedPatches = Invoke-PatchSeries $Libssh2Src $Libssh2Tag
if (-not $SkipOpenSSL) { Get-OpenSslSource }

if ($Clean -and (Test-Path -LiteralPath $BuildRoot)) {
    Write-Step 'removing thirdparty\build'
    Remove-Item -LiteralPath $BuildRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null

# ============================================================================
# OpenSSL (out-of-tree, both architectures in parallel)
# ============================================================================
function Get-OpenSslPrefix([string]$A) { Join-Path $BuildRoot "openssl-$A-install" }

# Everything that determines an OpenSSL build. Stored next to the install so
# -SkipOpenSSL can prove the existing libcrypto matches the current pins.
function Get-OpenSslStamp([string]$A) {
    "$OpenSslVersion|$OpenSslSha256|$($OpenSslOptions -join ' ')|$DependencyCFlags|$A|MSVC $($Toolchain.Targets[$A].MsvcVersion)"
}
function Get-OpenSslStampPath([string]$A) { Join-Path (Get-OpenSslPrefix $A) '.sftpplug-openssl' }

if (-not $SkipOpenSSL) {
    Write-Section "OpenSSL $OpenSslVersion"
    $nasmDir = Split-Path -Parent $Nasm
    $perlDir = Split-Path -Parent $Perl
    $steps = foreach ($a in $Archs) {
        $target = if ($a -eq 'x64') { 'VC-WIN64A' } else { 'VC-WIN32' }
        $work = Join-Path $BuildRoot "openssl-$a"
        $prefix = Get-OpenSslPrefix $a
        foreach ($d in $work, $prefix) { if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force } }
        # OpenSSL 4.1.0 Configure writes apps\include\configuration.h even with
        # no-apps, but an out-of-tree build directory never gets that folder.
        New-Item -ItemType Directory -Path (Join-Path $work 'apps\include') -Force | Out-Null
        $make = if ($Jom) { "`"$Jom`" -j $([Environment]::ProcessorCount)" } else { 'nmake -nologo' }
        $extra = if ($Jom) { '/FS' } else { '' }
        $configure = "`"$Perl`" `"$OpenSslSrc\Configure`" $target $($OpenSslOptions -join ' ') /MT $DependencyCFlags $extra --prefix=`"$prefix`" --openssldir=`"$prefix\ssl`""
        $body = @"
cd /d "$work" || exit /b 1
$configure || exit /b 2
$make build_libs || exit /b 3
$make install_dev || exit /b 4
"@
        Start-SftpDevShellStep -Toolchain $Toolchain -Arch $a -Name "OpenSSL $a" -LogPath (Join-Path $LogRoot "openssl-$a.log") -Body $body -PrependPath @($nasmDir, $perlDir)
    }
    Wait-SftpDevShellSteps -Steps @($steps)
    foreach ($a in $Archs) {
        $lib = Join-Path (Get-OpenSslPrefix $a) 'lib\libcrypto.lib'
        if (-not (Test-Path -LiteralPath $lib)) { throw "OpenSSL $a finished without $lib" }
        Set-Content -LiteralPath (Get-OpenSslStampPath $a) -Value (Get-OpenSslStamp $a) -Encoding UTF8
    }
} else {
    foreach ($a in $Archs) {
        $stampPath = Get-OpenSslStampPath $a
        $stamp = if (Test-Path -LiteralPath $stampPath) { (Get-Content -LiteralPath $stampPath -Raw).Trim() } else { '' }
        if ($stamp -ne (Get-OpenSslStamp $a)) {
            throw "-SkipOpenSSL: the existing OpenSSL $a was built from different inputs. Run without -SkipOpenSSL."
        }
    }
    Write-Step 'existing OpenSSL matches the current pins'
}

# ============================================================================
# libssh2 (CMake + NMake)
# ============================================================================
function Get-CMakeBody([string]$Source, [string]$Work, [string[]]$Defines) {
    $common = @(
        '-G', '"NMake Makefiles"',
        '-DCMAKE_BUILD_TYPE=Release',
        '-DCMAKE_POLICY_DEFAULT_CMP0091=NEW',
        '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded',
        "-DCMAKE_C_FLAGS_RELEASE=`"/MT /O2 /Ob2 /DNDEBUG /Z7 $DependencyCFlags`""
    ) + $Defines
    return @"
"$CMake" -S "$Source" -B "$Work" $($common -join ' ') || exit /b 5
"$CMake" --build "$Work" || exit /b 6
"@
}

Write-Section 'libssh2'
$steps = foreach ($a in $Archs) {
    $prefix = Get-OpenSslPrefix $a
    if (-not (Test-Path -LiteralPath (Join-Path $prefix 'lib\libcrypto.lib'))) { throw "OpenSSL $a is not built; run without -SkipOpenSSL." }
    $sshWork = Join-Path $BuildRoot "libssh2-$a"
    if (Test-Path -LiteralPath $sshWork) { Remove-Item -LiteralPath $sshWork -Recurse -Force }

    $sshBody = Get-CMakeBody $Libssh2Src $sshWork @(
        '-DCRYPTO_BACKEND=OpenSSL', "-DOPENSSL_ROOT_DIR=`"$prefix`"", '-DOPENSSL_USE_STATIC_LIBS=TRUE',
        '-DBUILD_SHARED_LIBS=OFF', '-DBUILD_STATIC_LIBS=ON', '-DBUILD_EXAMPLES=OFF', '-DBUILD_TESTING=OFF',
        '-DENABLE_ZLIB_COMPRESSION=OFF'
    )
    Start-SftpDevShellStep -Toolchain $Toolchain -Arch $a -Name "libssh2 $a" -LogPath (Join-Path $LogRoot "libssh2-$a.log") -Body $sshBody
}
Wait-SftpDevShellSteps -Steps @($steps)

# ============================================================================
# Install into src\
# ============================================================================
Write-Section 'Install'
New-Item -ItemType Directory -Path $LibDest, $HeaderDest -Force | Out-Null

function Install-File([string]$Source, [string]$Dest) {
    if (-not (Test-Path -LiteralPath $Source)) { throw "missing build output $Source" }
    Copy-Item -LiteralPath $Source -Destination $Dest -Force
    Write-Ok ("{0,-28} {1,8:N0} KB" -f (Split-Path $Dest -Leaf), ((Get-Item -LiteralPath $Dest).Length / 1KB))
}

foreach ($h in 'libssh2.h', 'libssh2_sftp.h', 'libssh2_publickey.h') {
    Copy-Item -LiteralPath (Join-Path $Libssh2Src "include\$h") -Destination (Join-Path $HeaderDest $h) -Force
}
Write-Ok 'libssh2 headers -> src\include\libssh2'

# The manifest records, per architecture, what its libraries were built from.
# build.ps1 recomputes the digest and the library hashes and refuses to link
# libraries that are stale or were replaced.
$previous = if (Test-Path -LiteralPath $Manifest) { Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json } else { $null }
$targets = [ordered]@{}
if ($previous -and $previous.PSObject.Properties['targets']) {
    foreach ($p in $previous.targets.PSObject.Properties) { if ($p.Name -notin $Archs) { $targets[$p.Name] = $p.Value } }
}
$digest = Get-SftpDependencyDigest
$libssh2Commit = "$((Invoke-Native -Exe $Git -Arguments @('-C', $Libssh2Src, 'rev-parse', 'HEAD') -Quiet).Output)".Trim()
foreach ($a in $Archs) {
    $sshLib = Get-ChildItem -LiteralPath (Join-Path $BuildRoot "libssh2-$a") -Filter 'libssh2.lib' -Recurse | Select-Object -First 1
    if (-not $sshLib) { throw "libssh2.lib not produced for $a" }
    Install-File (Join-Path (Get-OpenSslPrefix $a) 'lib\libcrypto.lib') (Join-Path $LibDest "libcrypto_$a.lib")
    Install-File $sshLib.FullName (Join-Path $LibDest "libssh2_$a.lib")
    # OpenSSL headers are per target (configuration.h differs between x64 and x86).
    $headerTarget = Join-Path $LibDest "include-$a"
    if (Test-Path -LiteralPath $headerTarget) { Remove-Item -LiteralPath $headerTarget -Recurse -Force }
    Copy-Item -LiteralPath (Join-Path (Get-OpenSslPrefix $a) 'include') -Destination $headerTarget -Recurse
    Write-Ok "OpenSSL headers -> src\lib\include-$a"

    $targets[$a] = [ordered]@{
        digest    = $digest
        toolchain = "MSVC $($Toolchain.Targets[$a].MsvcVersion), Windows SDK $($Toolchain.WindowsSdk.Version)"
        openssl   = "$OpenSslVersion sha256:$OpenSslSha256"
        libssh2   = "$Libssh2Tag $libssh2Commit + $($AppliedPatches.Count) patches"
        libraries = [ordered]@{
            "libcrypto_$a.lib" = Get-Sha256 (Join-Path $LibDest "libcrypto_$a.lib")
            "libssh2_$a.lib"   = Get-Sha256 (Join-Path $LibDest "libssh2_$a.lib")
        }
    }
}
[ordered]@{ targets = $targets } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Manifest -Encoding UTF8

Write-Host ''
Write-Host 'Dependencies built. Next: .\build.ps1' -ForegroundColor Cyan
