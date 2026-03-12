$ErrorActionPreference = "Stop"

function Get-RegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    try {
        return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    } catch {
        return $null
    }
}

function Get-TotalCommanderDir {
    $candidates = @(
        (Get-RegistryValue -Path "HKCU:\Software\Ghisler\Total Commander" -Name "InstallDir"),
        (Get-RegistryValue -Path "HKLM:\Software\Ghisler\Total Commander" -Name "InstallDir"),
        (Get-RegistryValue -Path "HKLM:\Software\WOW6432Node\Ghisler\Total Commander" -Name "InstallDir"),
        $env:COMMANDER_PATH
    ) | Where-Object { $_ -and (Test-Path $_) }

    if ($candidates.Count -gt 0) {
        return $candidates[0]
    }

    Write-Host "Nie znaleziono katalogu Total Commandera automatycznie." -ForegroundColor Yellow
    $manualPath = Read-Host "Podaj pelna sciezke do folderu Total Commandera (np. C:\totalcmd)"
    if (-not (Test-Path $manualPath)) {
        throw "Podana sciezka nie istnieje: $manualPath"
    }
    return $manualPath
}

function Get-WinCmdIniPath {
    param([Parameter(Mandatory = $true)][string]$TcDir)

    $iniFromRegistry = Get-RegistryValue -Path "HKCU:\Software\Ghisler\Total Commander" -Name "IniFileName"
    if ($iniFromRegistry -and (Test-Path $iniFromRegistry)) {
        return $iniFromRegistry
    }

    $iniInTcDir = Join-Path $TcDir "wincmd.ini"
    if (Test-Path $iniInTcDir) {
        return $iniInTcDir
    }

    $iniInAppData = Join-Path $env:APPDATA "GHISLER\wincmd.ini"
    if (Test-Path $iniInAppData) {
        return $iniInAppData
    }

    return $iniInAppData
}

function Set-IniEntry {
    param(
        [Parameter(Mandatory = $true)][string]$IniPath,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Entry
    )

    $section = "[$Section]"
    $raw = ""

    if (Test-Path $IniPath) {
        $raw = Get-Content -Path $IniPath -Raw -ErrorAction SilentlyContinue
    }
    if (-not $raw) {
        $raw = ""
    }

    if ($raw -match "(?im)^\[$([regex]::Escape($Section))\]\s*$") {
        $entryKey = [regex]::Escape(($Entry -split "=")[0])
        if ($raw -match "(?im)^$entryKey=.*$") {
            $raw = [regex]::Replace($raw, "(?im)^$entryKey=.*$", [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $Entry }, 1)
        } else {
            $raw = [regex]::Replace(
                $raw,
                "(?im)(^\[$([regex]::Escape($Section))\]\s*$)",
                [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $m.Groups[1].Value + "`r`n" + $Entry },
                1
            )
        }
    } else {
        if ($raw.Length -gt 0 -and -not $raw.EndsWith("`r`n")) {
            $raw += "`r`n"
        }
        $raw += "$section`r`n$Entry`r`n"
    }

    $iniDir = Split-Path -Parent $IniPath
    if (-not (Test-Path $iniDir)) {
        New-Item -Path $iniDir -ItemType Directory -Force | Out-Null
    }

    Set-Content -Path $IniPath -Value $raw -Encoding Default
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$tcDir = Get-TotalCommanderDir

$packagedPluginDir = Join-Path $scriptDir "plugins\wfx\sftpplug"
$sourceX64 = Join-Path $packagedPluginDir "sftpplug.wfx64"

$targetDir = Join-Path $tcDir "Plugins\WFX\SFTPplug"
$targetX64 = Join-Path $targetDir "sftpplug.wfx64"

New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
if (Test-Path $sourceX64) {
    Copy-Item -Path $sourceX64 -Destination $targetX64 -Force
}
if (-not (Test-Path $targetX64)) {
    throw "Brak pliku pluginu x64 (sftpplug.wfx64). Uruchom najpierw build\\build.ps1."
}

$runtimeDlls = @(
    "libssh2.dll",
    "libcrypto-3-x64.dll",
    "libssl-3-x64.dll",
    "libcrypto-3.dll",
    "libssl-3.dll",
    "libcrypto.dll",
    "libssl.dll"
)

foreach ($dll in $runtimeDlls) {
    $dllSrc = Join-Path $packagedPluginDir $dll
    if (Test-Path $dllSrc) {
        Copy-Item -Path $dllSrc -Destination (Join-Path $targetDir $dll) -Force
    }
}

$iniPath = Get-WinCmdIniPath -TcDir $tcDir
Set-IniEntry -IniPath $iniPath -Section "FileSystemPlugins64" -Entry "sftp=1"

Write-Host ""
Write-Host "Instalacja zakonczona powodzeniem." -ForegroundColor Green
Write-Host "Total Commander: $tcDir"
Write-Host "Plugin x64: $targetX64"
Write-Host "INI: $iniPath"
Write-Host ""
Write-Host "Uruchom ponownie Total Commandera, jesli byl otwarty." -ForegroundColor Yellow
