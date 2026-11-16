#requires -Version 7
<#
.SYNOPSIS
LAN Pair between this computer and another Windows computer on the network.

.DESCRIPTION
Builds tests\lanpair\LanPairPeer.cpp - the plugin's own LAN Pair sources in a
console program - copies it to the other computer through its administrative
share and runs it there, over ssh, as the LAN Pair file server. Here it runs as
the client: pairing with a fresh random password, a 16 MiB round trip with a
UTF-8 file name, rename and delete, a second session on the stored keys, and a
refused wrong password.

The other computer needs ssh and C$ access with administrator rights. For the
length of the test it gets one inbound firewall rule, for the test program and
port and for this computer's address only. Afterwards the rule, the program,
every file it made and the test keys on both computers are removed, whatever
the outcome.

.PARAMETER RemoteHost
Name or address of the other computer, as ssh and \\host\C$ reach it.

.PARAMETER Port
TCP port for the test server (default 45899, away from LAN Pair's own 45846).
#>
param(
    [Parameter(Mandatory)] [string]$RemoteHost,
    [int]$Port = 45899
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
$Root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $Root 'tools\Toolchain.psm1') -Force

# ---- build ----------------------------------------------------------------
$Sources = @(
    'tests\lanpair\LanPairPeer.cpp',
    'src\core\LanPairProtocol.cpp',
    'src\core\LanPair.cpp',
    'src\core\LanPairSession.cpp',
    'src\core\TrustedInstallerToken.cpp',
    'src\core\DllExceptionBarrier.cpp'
) | ForEach-Object { "`"$(Join-Path $Root $_)`"" }
$Toolchain = Get-SftpToolchain -Arch @('x64')
Write-SftpToolchainSummary $Toolchain
$crypto = Join-Path $Root 'src\lib\libcrypto_x64.lib'
$osslInclude = Join-Path $Root 'src\lib\include-x64'
if (-not (Test-Path $crypto)) { throw 'OpenSSL for x64 is not built. Run .\build-deps.ps1 first.' }
$out = Join-Path $PSScriptRoot 'out\lanpair-peer-x64'
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Path $out -Force | Out-Null
$exe = Join-Path $out 'lanpair_peer.exe'
$body = @"
cd /d "$out" || exit /b 1
cl /nologo /std:c++20 /EHsc /W4 /WX /permissive- /utf-8 /DUNICODE /D_UNICODE /DNOMINMAX /DWIN32_LEAN_AND_MEAN /MT /O2 /DNDEBUG /I"$(Join-Path $Root 'src\include')" /I"$osslInclude" $($Sources -join ' ') /Fe:"$exe" /Fo:"$out\\" /link "$crypto" ws2_32.lib crypt32.lib advapi32.lib user32.lib bcrypt.lib iphlpapi.lib shell32.lib ole32.lib dbghelp.lib || exit /b 2
"@
Invoke-SftpDevShellStep -Toolchain $Toolchain -Arch 'x64' -Name 'compile LAN Pair peer' -LogPath (Join-Path $out 'build.log') -Body $body

# ---- addresses, names, secrets -------------------------------------------
$remoteIp = (Resolve-DnsName $RemoteHost -Type A -ErrorAction Stop | Where-Object IPAddress | Select-Object -First 1).IPAddress
$localIp = (Find-NetRoute -RemoteIPAddress $remoteIp | Where-Object { $_.PSObject.Properties['IPAddress'] } | Select-Object -First 1).IPAddress
$tag = "sftpplug-lanpair-test-$PID"
$remoteDir = "C:\ProgramData\$tag"
$share = "\\$RemoteHost\C$\ProgramData\$tag"
$serverId = "sftpplug-test-srv-$PID"
$clientId = "sftpplug-test-cli-$PID"
$password = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(18))
$serverLog = Join-Path $out 'server.log'
Write-Host "  this computer $localIp -> other computer $remoteIp, port $Port" -ForegroundColor Gray

function Invoke-Remote([string]$Command) {
    $result = ssh -o BatchMode=yes -o ConnectTimeout=10 $RemoteHost $Command 2>&1
    return @($result | ForEach-Object { "$_" })
}

# The key store lives in the profile of the account ssh runs under; a store
# the test had to create is removed with it.
$remoteAppData = (Invoke-Remote 'echo %APPDATA%' | Select-Object -Last 1).Trim()
if ($remoteAppData -notmatch '^[A-Za-z]:\\') { throw "Cannot read %APPDATA% on $RemoteHost." }
$remoteSecrets = "\\$RemoteHost\$($remoteAppData.Substring(0, 1))$" + $remoteAppData.Substring(2) + '\GHISLER\sftpplug.secrets'
$localSecrets = Join-Path $env:APPDATA 'GHISLER\sftpplug.secrets'
$secretStores = @(@{ Path = $remoteSecrets; Existed = (Test-Path $remoteSecrets) },
                  @{ Path = $localSecrets;  Existed = (Test-Path $localSecrets) })

$server = $null
$exitCode = 1
try {
    New-Item -ItemType Directory -Path $share -Force | Out-Null
    Copy-Item $exe $share
    Invoke-Remote "netsh advfirewall firewall add rule name=$tag dir=in action=allow protocol=TCP localport=$Port remoteip=$localIp program=`"$remoteDir\lanpair_peer.exe`" enable=yes" | Out-Null

    $server = Start-Process ssh -ArgumentList @('-o', 'BatchMode=yes', $RemoteHost,
        "`"$remoteDir\lanpair_peer.exe`" serve 0.0.0.0 $Port $serverId $password 180 `"$remoteDir\stop`"") `
        -RedirectStandardOutput $serverLog -RedirectStandardError (Join-Path $out 'server.err') -NoNewWindow -PassThru
    $deadline = (Get-Date).AddSeconds(30)
    while (-not ((Test-Path $serverLog) -and (Select-String -Path $serverLog -Pattern 'READY|FAIL' -Quiet))) {
        if ((Get-Date) -gt $deadline -or $server.HasExited) { throw 'The server on the other computer did not start.' }
        Start-Sleep -Milliseconds 250
    }
    if (Select-String -Path $serverLog -Pattern 'FAIL' -Quiet) { throw "Server: $(Get-Content $serverLog -Raw)" }

    & $exe client $remoteIp $Port $clientId $serverId $password "$remoteDir\files" | ForEach-Object { Write-Host "  $_" }
    $exitCode = $LASTEXITCODE
} finally {
    # Everything goes, whatever happened above.
    if (Test-Path $share) { New-Item -ItemType File -Path (Join-Path $share 'stop') -Force | Out-Null }
    if ($server) { $server | Wait-Process -Timeout 20 -ErrorAction SilentlyContinue; if (-not $server.HasExited) { $server | Stop-Process -Force } }
    Invoke-Remote "`"$remoteDir\lanpair_peer.exe`" forget $serverId $clientId" | Out-Null
    & $exe forget $serverId $clientId | Out-Null
    Invoke-Remote "netsh advfirewall firewall delete rule name=$tag" | Out-Null
    Start-Sleep -Milliseconds 500
    if (Test-Path $share) { Remove-Item $share -Recurse -Force -ErrorAction SilentlyContinue }

    foreach ($store in $secretStores) {
        if (-not $store.Existed -and (Test-Path $store.Path) -and -not (Get-ChildItem $store.Path -Force)) {
            Remove-Item $store.Path -Force
        }
    }

    $ruleLeft = (Invoke-Remote "netsh advfirewall firewall show rule name=$tag") -match 'Rule Name'
    $leftovers = @()
    if ($ruleLeft) { $leftovers += 'firewall rule' }
    if (Test-Path $share) { $leftovers += $share }
    foreach ($store in $secretStores) {
        if (Get-ChildItem (Join-Path $store.Path "*sftpplug-test-*$PID*") -ErrorAction SilentlyContinue) { $leftovers += "test keys in $($store.Path)" }
        if (-not $store.Existed -and (Test-Path $store.Path)) { $leftovers += $store.Path }
    }
    if ($leftovers) {
        Write-Host "  LEFT BEHIND: $($leftovers -join ', ')" -ForegroundColor Red
        $exitCode = 1
    } else {
        Write-Host '  cleaned up: firewall rule, program, files and test keys on both computers' -ForegroundColor Gray
    }
}
exit $exitCode
