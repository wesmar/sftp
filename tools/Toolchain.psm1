#requires -Version 5.1
<#
.SYNOPSIS
Toolchain discovery shared by build-deps.ps1, build.ps1 and the test runners.

.DESCRIPTION
Nothing here is pinned to a Visual Studio, MSVC or Windows SDK version.
Every candidate is accepted only on evidence: the compiler, linker,
librarian, assembler, nmake, CRT import libraries and headers that a build
for the requested target actually uses must exist on disk. Versions are
always compared as [version], never as text.

Personal tool locations (portable Perl, CMake, ...) belong in an untracked
build.local.psd1 next to build.ps1, or in SFTPPLUG_<TOOL> environment
variables, e.g. SFTPPLUG_PERL. See build.local.example.psd1.
#>
Set-StrictMode -Version 3.0

$script:RepoRoot = Split-Path $PSScriptRoot -Parent

$script:Targets = @{
    x64   = [pscustomobject]@{ Dir = 'x64';   Assembler = 'ml64.exe';     MSBuildPlatform = 'x64' }
    x86   = [pscustomobject]@{ Dir = 'x86';   Assembler = 'ml.exe';       MSBuildPlatform = 'Win32' }
    arm64 = [pscustomobject]@{ Dir = 'arm64'; Assembler = 'armasm64.exe'; MSBuildPlatform = 'ARM64' }
}

function Get-SftpHostArchs {
    <#
    Compiler host architectures to try, the machine's own first: Windows on
    Arm runs the native arm64-hosted compilers, an x64 machine the x64 ones;
    the others are fallbacks (emulated, or 32-bit).
    #>
    $os = "$([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)"
    if ($os -eq 'Arm64') { return @('arm64', 'x64', 'x86') }
    return @('x64', 'x86')
}

function Select-SftpArch {
    <#
    The architectures a script was asked for by its -amd64 (-x64), -x86 and
    -arm64 switches, in build order; no switch at all means every one.
    #>
    param([switch]$Amd64, [switch]$X86, [switch]$Arm64)
    $chosen = @()
    if ($Amd64) { $chosen += 'x64' }
    if ($X86)   { $chosen += 'x86' }
    if ($Arm64) { $chosen += 'arm64' }
    if ($chosen.Count -eq 0) { $chosen = @('x64', 'x86', 'arm64') }
    return $chosen
}

function Test-SftpArchRunnable {
    <#
    Whether this machine can run programs built for an architecture: Windows
    on Arm runs arm64 natively and x64/x86 under emulation; an x64 machine
    cannot run arm64.
    #>
    param([Parameter(Mandatory)] [ValidateSet('x64', 'x86', 'arm64')] [string]$Arch)
    $os = "$([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)"
    return $os -eq 'Arm64' -or $Arch -ne 'arm64'
}

function Resolve-SftpTestArch {
    <#
    Maps a test runner's -Arch value to architectures: x64, x86, arm64, both
    (x64 + x86), all, or empty - what this machine can run.
    #>
    param([string]$Arch)
    switch ($Arch) {
        'both'  { return @('x64', 'x86') }
        'all'   { return @('x64', 'x86', 'arm64') }
        ''      { return @(@('x64', 'x86', 'arm64') | Where-Object { Test-SftpArchRunnable $_ }) }
        default { return @($Arch) }
    }
}

function ConvertTo-SftpVersion {
    param([string]$Text)
    $parsed = $null
    if ($Text -and [version]::TryParse($Text, [ref]$parsed)) { return $parsed }
    return $null
}

function Get-SftpLocalOverrides {
    $path = Join-Path $script:RepoRoot 'build.local.psd1'
    if (Test-Path -LiteralPath $path) { return Import-PowerShellDataFile -LiteralPath $path }
    return @{}
}

function Find-SftpBuildTool {
    <#
    Returns the first existing, valid executable from: build.local.psd1,
    SFTPPLUG_<NAME>, PATH, then the caller's well-known locations.
    #>
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$Executable,
        [string[]]$Candidates = @(),
        [scriptblock]$Validate
    )
    $search = [System.Collections.Generic.List[string]]::new()
    $overrides = Get-SftpLocalOverrides
    if ($overrides.ContainsKey($Name) -and $overrides[$Name]) { $search.Add([string]$overrides[$Name]) }
    $fromEnv = [Environment]::GetEnvironmentVariable("SFTPPLUG_$($Name.ToUpperInvariant())")
    if ($fromEnv) { $search.Add($fromEnv) }
    foreach ($cmd in @(Get-Command $Executable -All -CommandType Application -ErrorAction SilentlyContinue)) {
        $search.Add($cmd.Source)
    }
    foreach ($c in $Candidates) { if ($c) { $search.Add($c) } }

    foreach ($path in $search) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        if ($Validate -and -not (& $Validate $path)) { continue }
        return (Resolve-Path -LiteralPath $path).Path
    }
    return $null
}

function Get-SftpVisualStudioInstances {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        throw 'vswhere.exe not found. Install Visual Studio 2022 or later with the "Desktop development with C++" workload.'
    }
    # -products * also lists products without a C++ compiler (e.g. SQL Server
    # Management Studio); those are filtered out by the evidence checks below.
    $json = (& $vswhere -all -prerelease -products * -format json -utf8) -join "`n"
    @($json | ConvertFrom-Json) |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.installationPath 'VC\Tools\MSVC') } |
        Sort-Object { ConvertTo-SftpVersion $_.installationVersion } -Descending
}

function Find-SftpMsvc {
    <#
    Newest MSVC version under a VS instance that can build the target, with
    the host architecture whose bin directory is complete. The machine's own
    architecture is preferred (Get-SftpHostArchs); another host is accepted
    when only that one is installed.
    #>
    param(
        [Parameter(Mandatory)] [string]$VsPath,
        [Parameter(Mandatory)] [ValidateSet('x64', 'x86', 'arm64')] [string]$Arch
    )
    $target = $script:Targets[$Arch]
    $root = Join-Path $VsPath 'VC\Tools\MSVC'
    $versions = Get-ChildItem -LiteralPath $root -Directory |
        Where-Object { ConvertTo-SftpVersion $_.Name } |
        Sort-Object { ConvertTo-SftpVersion $_.Name } -Descending

    foreach ($v in $versions) {
        if (-not (Test-Path -LiteralPath (Join-Path $v.FullName 'include\vcruntime.h'))) { continue }
        $libDir = Join-Path $v.FullName "lib\$($target.Dir)"
        if (-not ((Test-Path (Join-Path $libDir 'libcmt.lib')) -and (Test-Path (Join-Path $libDir 'libvcruntime.lib')))) { continue }

        foreach ($hostArch in (Get-SftpHostArchs)) {
            $bin = Join-Path $v.FullName "bin\Host$hostArch\$($target.Dir)"
            $required = @('cl.exe', 'link.exe', 'lib.exe', 'nmake.exe', $target.Assembler)
            $missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $bin $_)) })
            if ($missing.Count -eq 0) {
                return [pscustomobject]@{
                    Version  = $v.Name
                    HostArch = $hostArch
                    BinDir   = $bin
                }
            }
        }
    }
    return $null
}

function Get-SftpPlatformToolset {
    <#
    Maps an MSVC version to the MSBuild platform toolset that owns it, using
    the version props Visual Studio installs (VC\Auxiliary\Build\v<NNN>\
    Microsoft.VCToolsVersion.VC.<major.minor>.props), then confirms MSBuild
    knows that toolset for the platform.
    #>
    param(
        [Parameter(Mandatory)] [string]$VsPath,
        [Parameter(Mandatory)] [string]$MsvcVersion,
        [Parameter(Mandatory)] [string]$MSBuildPlatform
    )
    $wanted = ConvertTo-SftpVersion $MsvcVersion
    $aux = Join-Path $VsPath 'VC\Auxiliary\Build'
    $owners = [System.Collections.Generic.List[string]]::new()

    foreach ($dir in @(Get-ChildItem -LiteralPath $aux -Directory -Filter 'v*' -ErrorAction SilentlyContinue)) {
        foreach ($props in @(Get-ChildItem -LiteralPath $dir.FullName -Filter 'Microsoft.VCToolsVersion.VC.*.props')) {
            $v = ConvertTo-SftpVersion ($props.Name -replace '^Microsoft\.VCToolsVersion\.VC\.(.+)\.props$', '$1')
            if ($v -and $v.Major -eq $wanted.Major -and $v.Minor -eq $wanted.Minor) { $owners.Add($dir.Name); break }
        }
    }
    # Older layouts only ship Microsoft.VCToolsVersion.v<NNN>.default.txt.
    if ($owners.Count -eq 0) {
        foreach ($txt in @(Get-ChildItem -LiteralPath $aux -Filter 'Microsoft.VCToolsVersion.v*.default.txt')) {
            $v = ConvertTo-SftpVersion (Get-Content -LiteralPath $txt.FullName -Raw).Trim()
            if ($v -and $v.Major -eq $wanted.Major -and $v.Minor -eq $wanted.Minor) {
                $owners.Add(($txt.Name -replace '^Microsoft\.VCToolsVersion\.(v\d+)\.default\.txt$', '$1'))
            }
        }
    }

    $vcRoot = Join-Path $VsPath 'MSBuild\Microsoft\VC'
    foreach ($toolset in $owners) {
        $known = @(Get-ChildItem -LiteralPath $vcRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "Platforms\$MSBuildPlatform\PlatformToolsets\$toolset") })
        if ($known.Count -gt 0) { return $toolset }
    }
    return $null
}

function Find-SftpWindowsSdk {
    <#
    Newest Windows 10/11 SDK whose headers, CRT and Win32 import libraries for
    every requested target, and rc.exe for the host, are all present.
    #>
    param(
        [Parameter(Mandatory)] [string[]]$Arch,
        [Parameter(Mandatory)] [string]$HostArch
    )
    $roots = [System.Collections.Generic.List[string]]::new()
    try {
        $roots.Add((Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' -Name KitsRoot10 -ErrorAction Stop).TrimEnd('\'))
    } catch { }
    $roots.Add((Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'))

    foreach ($root in ($roots | Select-Object -Unique)) {
        $include = Join-Path $root 'Include'
        if (-not (Test-Path -LiteralPath $include)) { continue }
        $versions = Get-ChildItem -LiteralPath $include -Directory |
            Where-Object { ConvertTo-SftpVersion $_.Name } |
            Sort-Object { ConvertTo-SftpVersion $_.Name } -Descending
        foreach ($v in $versions) {
            $n = $v.Name
            $ok = (Test-Path "$include\$n\um\windows.h") -and (Test-Path "$include\$n\ucrt\stdio.h") -and
                  (Test-Path "$root\bin\$n\$HostArch\rc.exe")
            foreach ($a in $Arch) {
                $ok = $ok -and (Test-Path "$root\Lib\$n\um\$a\kernel32.lib") -and (Test-Path "$root\Lib\$n\ucrt\$a\libucrt.lib")
            }
            if ($ok) { return [pscustomobject]@{ Version = $n; Root = $root; RcExe = "$root\bin\$n\$HostArch\rc.exe" } }
        }
    }
    return $null
}

function Get-SftpToolchain {
    <#
    Picks the newest Visual Studio instance that can build every requested
    architecture, and returns everything a build step needs.
    #>
    param([ValidateSet('x64', 'x86', 'arm64')] [string[]]$Arch = @('x64', 'x86', 'arm64'))

    $rejected = [System.Collections.Generic.List[string]]::new()
    foreach ($vs in @(Get-SftpVisualStudioInstances)) {
        $vsPath = $vs.installationPath
        $vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvarsall.bat'
        $msbuild = @(
            (Join-Path $vsPath 'MSBuild\Current\Bin\amd64\MSBuild.exe'),
            (Join-Path $vsPath 'MSBuild\Current\Bin\MSBuild.exe')
        ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if (-not (Test-Path -LiteralPath $vcvars)) { $rejected.Add("$($vs.displayName): no vcvarsall.bat"); continue }
        if (-not $msbuild) { $rejected.Add("$($vs.displayName): no MSBuild.exe"); continue }

        $perArch = @{}
        $complete = $true
        foreach ($a in $Arch) {
            $msvc = Find-SftpMsvc -VsPath $vsPath -Arch $a
            if (-not $msvc) { $rejected.Add("$($vs.displayName): no complete MSVC for $a"); $complete = $false; break }
            $platform = $script:Targets[$a].MSBuildPlatform
            $toolset = Get-SftpPlatformToolset -VsPath $vsPath -MsvcVersion $msvc.Version -MSBuildPlatform $platform
            if (-not $toolset) { $rejected.Add("$($vs.displayName): MSVC $($msvc.Version) has no MSBuild toolset for $platform"); $complete = $false; break }
            $vcvarsArch = if ($msvc.HostArch -eq $a) { $a } else { "$($msvc.HostArch)_$a" }
            $perArch[$a] = [pscustomobject]@{
                Arch            = $a
                MSBuildPlatform = $platform
                MsvcVersion     = $msvc.Version
                HostArch        = $msvc.HostArch
                BinDir          = $msvc.BinDir
                VcVarsArch      = $vcvarsArch
                PlatformToolset = $toolset
            }
        }
        if (-not $complete) { continue }

        $sdk = $null
        foreach ($hostArch in (Get-SftpHostArchs)) {
            $sdk = Find-SftpWindowsSdk -Arch $Arch -HostArch $hostArch
            if ($sdk) { break }
        }
        if (-not $sdk) { $rejected.Add("$($vs.displayName): no complete Windows SDK"); continue }

        return [pscustomobject]@{
            VsName     = $vs.displayName
            VsVersion  = $vs.installationVersion
            VsPath     = $vsPath
            VcVarsAll  = $vcvars
            MSBuild    = $msbuild
            WindowsSdk = $sdk
            Targets    = $perArch
        }
    }
    $detail = if ($rejected.Count) { "`n  " + ($rejected -join "`n  ") } else { '' }
    throw "No Visual Studio installation can build $($Arch -join ' + ').$detail"
}

function Write-SftpToolchainSummary {
    param([Parameter(Mandatory)] $Toolchain)
    Write-Host "  Visual Studio : $($Toolchain.VsName) $($Toolchain.VsVersion)" -ForegroundColor Gray
    Write-Host "  Windows SDK   : $($Toolchain.WindowsSdk.Version)" -ForegroundColor Gray
    foreach ($t in $Toolchain.Targets.Values | Sort-Object Arch) {
        Write-Host ("  {0,-13} : MSVC {1} (host {2}, toolset {3})" -f $t.Arch, $t.MsvcVersion, $t.HostArch, $t.PlatformToolset) -ForegroundColor Gray
    }
}

function New-SftpDevShellScript {
    <#
    Returns the text of a cmd batch that enters the developer environment for
    one target and then runs Body. The batch refuses to continue unless
    vcvarsall really activated the MSVC version and target that were chosen.
    #>
    param(
        [Parameter(Mandatory)] $Toolchain,
        [Parameter(Mandatory)] [ValidateSet('x64', 'x86', 'arm64')] [string]$Arch,
        [Parameter(Mandatory)] [string]$Body,
        [string[]]$PrependPath = @()
    )
    $t = $Toolchain.Targets[$Arch]
    $lines = [System.Collections.Generic.List[string]]::new()
    $vswhereDir = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
    $lines.Add('@echo off')
    $lines.Add('setlocal enableextensions')
    # vcvarsall probes with vswhere; without it on PATH every step logs a spurious error.
    $lines.Add("set `"PATH=$vswhereDir;%PATH%`"")
    $lines.Add("call `"$($Toolchain.VcVarsAll)`" $($t.VcVarsArch) $($Toolchain.WindowsSdk.Version) -vcvars_ver=$($t.MsvcVersion) >nul")
    $lines.Add('if errorlevel 1 exit /b 90')
    # Some vcvarsall versions end VCToolsVersion with a backslash, others do not.
    $lines.Add('set "SFTP_ACTIVE_VCTOOLS=%VCToolsVersion:\=%"')
    $lines.Add("if /i not `"%SFTP_ACTIVE_VCTOOLS%`"==`"$($t.MsvcVersion)`" (echo vcvarsall activated MSVC %VCToolsVersion%, expected $($t.MsvcVersion) & exit /b 91)")
    $lines.Add("if /i not `"%VSCMD_ARG_TGT_ARCH%`"==`"$Arch`" (echo vcvarsall activated target %VSCMD_ARG_TGT_ARCH%, expected $Arch & exit /b 92)")
    if ($PrependPath.Count) { $lines.Add("set `"PATH=$($PrependPath -join ';');%PATH%`"") }
    $lines.Add($Body)
    return ($lines -join "`r`n") + "`r`n"
}

function Start-SftpDevShellStep {
    <#
    Starts one build step in its own cmd process and returns a handle for
    Wait-SftpDevShellSteps. Output goes to LogPath so parallel steps do not
    interleave.
    #>
    param(
        [Parameter(Mandatory)] $Toolchain,
        [Parameter(Mandatory)] [ValidateSet('x64', 'x86', 'arm64')] [string]$Arch,
        [Parameter(Mandatory)] [string]$Body,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$LogPath,
        [string[]]$PrependPath = @()
    )
    $script = New-SftpDevShellScript -Toolchain $Toolchain -Arch $Arch -Body $Body -PrependPath $PrependPath
    $logDir = Split-Path -Parent $LogPath
    if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $batch = [System.IO.Path]::ChangeExtension($LogPath, '.cmd')
    [System.IO.File]::WriteAllText($batch, $script, [System.Text.Encoding]::Default)

    $psi = [System.Diagnostics.ProcessStartInfo]::new($env:ComSpec, "/D /S /C `"`"$batch`" > `"$LogPath`" 2>&1`"")
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    Write-Host "  started  $Name" -ForegroundColor Gray
    return [pscustomobject]@{ Name = $Name; Process = $process; LogPath = $LogPath; Started = Get-Date }
}

function Wait-SftpDevShellSteps {
    param([Parameter(Mandatory)] [object[]]$Steps)
    $failed = [System.Collections.Generic.List[object]]::new()
    foreach ($s in $Steps) {
        $s.Process.WaitForExit()
        $elapsed = [int]((Get-Date) - $s.Started).TotalSeconds
        if ($s.Process.ExitCode -eq 0) {
            Write-Host ("  finished {0} ({1} s)" -f $s.Name, $elapsed) -ForegroundColor Green
        } else {
            Write-Host ("  FAILED   {0} (exit {1}, {2} s) - log: {3}" -f $s.Name, $s.Process.ExitCode, $elapsed, $s.LogPath) -ForegroundColor Red
            Get-Content -LiteralPath $s.LogPath -Tail 40 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
            $failed.Add($s)
        }
    }
    if ($failed.Count) { throw "Build step(s) failed: $(($failed | ForEach-Object Name) -join ', ')" }
}

function Invoke-SftpDevShellStep {
    param(
        [Parameter(Mandatory)] $Toolchain,
        [Parameter(Mandatory)] [ValidateSet('x64', 'x86', 'arm64')] [string]$Arch,
        [Parameter(Mandatory)] [string]$Body,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$LogPath,
        [string[]]$PrependPath = @()
    )
    $step = Start-SftpDevShellStep @PSBoundParameters
    Wait-SftpDevShellSteps -Steps @($step)
}

function Get-SftpDependencyDigest {
    <#
    SHA-256 over everything that decides what build-deps.ps1 produces: the
    script itself (pins, options), the libssh2 submodule commit and every
    patch. build-deps.ps1 records it; build.ps1 refuses stale libraries.
    #>
    $root = $script:RepoRoot
    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $root 'build-deps.ps1')).Hash)
    $gitlink = (& git -C $root ls-tree HEAD thirdparty/libssh2 2>$null) -split '\s+'
    $parts.Add($(if ($gitlink.Count -ge 3) { $gitlink[2] } else { 'no-submodule' }))
    $patches = Join-Path $root 'thirdparty\patches'
    if (Test-Path -LiteralPath $patches) {
        foreach ($f in Get-ChildItem -LiteralPath $patches -Recurse -File | Sort-Object FullName) {
            $parts.Add("$($f.FullName.Substring($root.Length)):$((Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName).Hash)")
        }
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($parts -join "`n"))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

Export-ModuleMember -Function Select-SftpArch, Test-SftpArchRunnable, Resolve-SftpTestArch, ConvertTo-SftpVersion, Find-SftpBuildTool, Get-SftpToolchain,
    Write-SftpToolchainSummary, New-SftpDevShellScript, Start-SftpDevShellStep,
    Wait-SftpDevShellSteps, Invoke-SftpDevShellStep, Get-SftpDependencyDigest
