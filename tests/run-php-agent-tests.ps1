#requires -Version 7.0
<#
.SYNOPSIS
Tests the PHP Agent (src\agent\sftp.php) and the plugin against it, locally.

.DESCRIPTION
Starts PHP's built-in web server on a free 127.0.0.1 port with a copy of the
agent in a temporary folder, twice: once with the PSK in an environment
variable, once with only its salted hash in the script - the form the plugin
writes. For each:

  1. protocol checks, without the plugin: signed requests pass; unsigned
     ones, the old clear-text header, a replayed nonce, an expired time, a
     wrong key, an altered parameter and an altered body are all refused -
     and a refused upload leaves its target untouched;
  2. the plugin's integration harness in PHP Agent mode.

The server is stopped and the folder deleted afterwards; nothing else on the
machine is touched.

.PARAMETER Php
php.exe to use. Default: the one on PATH, else C:\inetpub\php\php.exe or
C:\php\php.exe, whichever exists.

.PARAMETER Arch
Architectures for the integration harness: x64, x86 or both (default).

.PARAMETER SkipIntegration
Run the protocol checks only.
#>
param(
    [string]$Php,
    [ValidateSet('x64', 'x86', 'both')] [string]$Arch = 'both',
    [switch]$SkipIntegration
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
$Root = Split-Path $PSScriptRoot -Parent
$AgentSource = Join-Path $Root 'src\agent\sftp.php'
$Scheme = 'TCSFTP-HMAC-V2'

if (-not $Php) {
    $onPath = Get-Command php.exe -ErrorAction SilentlyContinue
    $Php = @($(if ($onPath) { $onPath.Source }), 'C:\inetpub\php\php.exe', 'C:\php\php.exe') |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
}
if (-not $Php -or -not (Test-Path -LiteralPath $Php)) { throw 'php.exe not found; pass -Php <path>.' }
Write-Host "php : $Php ($((& $Php -r 'echo PHP_VERSION;')))"

$script:passed = 0
$script:failed = 0
function Check([bool]$Ok, [string]$What) {
    if ($Ok) { $script:passed++; Write-Host "  ok   $What" } else { $script:failed++; Write-Host "  FAIL $What" -ForegroundColor Red }
}

function Get-Sha256Hex([byte[]]$Data) {
    # An empty array passed through a pipeline arrives as $null; a typed
    # variable keeps it an array.
    [byte[]]$bytes = [byte[]]::new(0)
    if ($null -ne $Data) { $bytes = $Data }
    -join ([System.Security.Cryptography.SHA256]::HashData($bytes) | ForEach-Object { $_.ToString('x2') })
}
function Get-HmacHex([string]$Key, [string]$Message) {
    $mac = [System.Security.Cryptography.HMACSHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Key), [Text.Encoding]::UTF8.GetBytes($Message))
    -join ($mac | ForEach-Object { $_.ToString('x2') })
}
function Get-RandomHex([int]$Bytes) {
    -join ([System.Security.Cryptography.RandomNumberGenerator]::GetBytes($Bytes) | ForEach-Object { $_.ToString('x2') })
}
# The query as the agent signs it: decoded, sorted by name then value, RFC 3986.
function Get-CanonicalQuery([string]$Query) {
    # Pairs go straight into a typed list: through a pipeline, a single
    # [name, value] pair would be unrolled into two loose strings.
    $pairs = [System.Collections.Generic.List[string[]]]::new()
    foreach ($part in $Query.Split('&')) {
        if (-not $part) { continue }
        $eq = $part.IndexOf('=')
        if ($eq -lt 0) { $pairs.Add([string[]]@([Uri]::UnescapeDataString($part), '')) }
        else { $pairs.Add([string[]]@([Uri]::UnescapeDataString($part.Substring(0, $eq)), [Uri]::UnescapeDataString($part.Substring($eq + 1)))) }
    }
    # Byte order, as PHP's strcmp - not the culture-aware order of Sort-Object.
    $pairs.Sort([Comparison[string[]]] { param($x, $y)
        $byName = [string]::CompareOrdinal($x[0], $y[0])
        if ($byName) { $byName } else { [string]::CompareOrdinal($x[1], $y[1]) } })
    $encoded = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $pairs) { $encoded.Add([Uri]::EscapeDataString($p[0]) + '=' + [Uri]::EscapeDataString($p[1])) }
    $encoded -join '&'
}

# Sends one request. -SignQuery / -SignBody sign something other than what is
# sent; -TimeShift moves the timestamp; -Headers replaces the auth headers.
function Invoke-Agent {
    param(
        [string]$Base, [string]$Method = 'GET', [string]$Op, [string]$Query = '', [byte[]]$Body = @(),
        [string]$Key, [string]$SignQuery, [byte[]]$SignBody, [int]$TimeShift = 0, [hashtable]$Headers
    )
    if (-not $Headers) {
        $ts = [string]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $TimeShift)
        $nonce = Get-RandomHex 16
        $bodySha = Get-Sha256Hex $(if ($PSBoundParameters.ContainsKey('SignBody')) { $SignBody } else { $Body })
        $signedQuery = if ($PSBoundParameters.ContainsKey('SignQuery')) { $SignQuery } else { $Query }
        $baseString = "$Scheme`n$Method`n$Op`n$(Get-CanonicalQuery $signedQuery)`n$bodySha`n$ts`n$nonce"
        $Headers = @{
            'X-SFTP-OP'             = $Op
            'X-SFTP-TS'             = $ts
            'X-SFTP-NONCE'          = $nonce
            'X-SFTP-CONTENT-SHA256' = Get-Sha256Hex $Body
            'X-SFTP-SIGNATURE-V2'   = Get-HmacHex $Key $baseString
        }
        if ($PSBoundParameters.ContainsKey('SignBody')) { $Headers['X-SFTP-CONTENT-SHA256'] = $bodySha }
    }
    $uri = if ($Query) { "$Base`?$Query" } else { $Base }
    $request = @{ Uri = $uri; Method = $Method; Headers = $Headers; SkipHttpErrorCheck = $true; UseBasicParsing = $true }
    if ($Body.Length) { $request['Body'] = $Body; $request['ContentType'] = 'application/octet-stream' }
    $r = Invoke-WebRequest @request
    $text = if ($r.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($r.Content) } else { [string]$r.Content }
    $code = ''
    try { $code = ($text | ConvertFrom-Json -ErrorAction Stop).error.code } catch { }
    [pscustomobject]@{ Status = [int]$r.StatusCode; Code = $code; Content = $text; Headers = $Headers }
}

function Get-FreePort {
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $l.Start(); $port = ($l.LocalEndpoint).Port; $l.Stop(); $port
}

function Test-Agent([string]$Name, [string]$Base, [string]$Key, [string]$Salt) {
    Write-Host "--- protocol ($Name)" -ForegroundColor Cyan
    $probe = Invoke-WebRequest -Uri "$Base`?op=PROBE" -UseBasicParsing -SkipHttpErrorCheck
    $info = $probe.Content | ConvertFrom-Json
    Check ($probe.StatusCode -eq 200 -and $info.auth.scheme -eq $Scheme -and $info.auth.salt -eq $Salt) "PROBE names $Scheme and the salt"

    $ok = Invoke-Agent -Base $Base -Op LIST -Query 'op=LIST&path=.&format=plain' -Key $Key
    Check ($ok.Status -eq 200) "a signed LIST passes ($($ok.Status) $($ok.Code))"

    $r = Invoke-Agent -Base $Base -Op LIST -Query 'op=LIST&path=.&format=plain' -Headers @{ 'X-SFTP-OP' = 'LIST' }
    Check ($r.Status -eq 401 -and $r.Code -eq 'AUTH_REQUIRED') "an unsigned request is refused ($($r.Status) $($r.Code))"

    $r = Invoke-Agent -Base $Base -Op LIST -Query 'op=LIST&path=.&format=plain' -Headers @{ 'X-SFTP-OP' = 'LIST'; 'X-SFTP-AUTH' = $script:psk }
    Check ($r.Status -eq 401) "the PSK in clear text (X-SFTP-AUTH) is refused ($($r.Status) $($r.Code))"

    $r = Invoke-Agent -Base $Base -Op LIST -Query 'op=LIST&path=.&format=plain' -Headers $ok.Headers
    Check ($r.Status -eq 401) "a replayed request is refused ($($r.Status) $($r.Code))"

    $r = Invoke-Agent -Base $Base -Op LIST -Query 'op=LIST&path=.&format=json' -SignQuery 'op=LIST&path=.&format=plain' -Key $Key
    Check ($r.Status -eq 401 -and $r.Code -eq 'BAD_SIGNATURE') "an altered parameter is refused ($($r.Status) $($r.Code))"

    $r = Invoke-Agent -Base $Base -Op LIST -Query 'op=LIST&path=.' -Key $Key -TimeShift -1000
    Check ($r.Status -eq 401 -and $r.Code -eq 'TIMESTAMP_EXPIRED') "an expired timestamp is refused ($($r.Status) $($r.Code))"

    $r = Invoke-Agent -Base $Base -Op LIST -Query 'op=LIST&path=.' -Key ('0' * 64)
    Check ($r.Status -eq 401 -and $r.Code -eq 'BAD_SIGNATURE') "a wrong key is refused ($($r.Status) $($r.Code))"

    $q = 'op=PUT&path=signed-put.txt&part=0&offset=0'
    $good = [Text.Encoding]::ASCII.GetBytes('original content')
    $r = Invoke-Agent -Base $Base -Method POST -Op PUT -Query $q -Body $good -Key $Key
    Check ($r.Status -eq 200) "a signed upload is stored ($($r.Status) $($r.Code))"
    $evil = [Text.Encoding]::ASCII.GetBytes('<?php system($_GET[1]);')
    $r = Invoke-Agent -Base $Base -Method POST -Op PUT -Query $q -Body $evil -SignBody $good -Key $Key
    Check ($r.Status -eq 401 -and $r.Code -eq 'BAD_CONTENT_HASH') "an upload with an altered body is refused ($($r.Status) $($r.Code))"
    $get = Invoke-Agent -Base $Base -Op GET -Query 'op=GET&path=signed-put.txt' -Key $Key
    Check ($get.Status -eq 200 -and $get.Content -eq 'original content') 'the refused upload left the file untouched'

    $list = [Text.Encoding]::UTF8.GetBytes("signed-put.txt`n")
    $r = Invoke-Agent -Base $Base -Method POST -Op TAR_PACK -Query 'op=TAR_PACK' -Body ([Text.Encoding]::UTF8.GetBytes("../../etc/passwd`n")) -SignBody $list -Key $Key
    Check ($r.Status -eq 401 -and $r.Code -eq 'BAD_CONTENT_HASH') "a TAR_PACK with an altered list is refused ($($r.Status) $($r.Code))"

    $r = Invoke-Agent -Base $Base -Op DELETE -Query 'op=DELETE&path=signed-put.txt' -Key $Key
    Check ($r.Status -eq 200) "the test file is deleted ($($r.Status) $($r.Code))"
}

$failedSteps = [System.Collections.Generic.List[string]]::new()
foreach ($config in 'psk-in-environment', 'salted-hash-in-script') {
    Write-Host ''
    Write-Host "=== agent with $config ===" -ForegroundColor Cyan
    $script:psk = Get-RandomHex 24
    $salt = ''
    $docroot = Join-Path ([System.IO.Path]::GetTempPath()) "sftpplug-php-$PID-$config"
    New-Item -ItemType Directory -Path $docroot -Force | Out-Null
    $script = [System.IO.File]::ReadAllText($AgentSource)
    if ($config -eq 'salted-hash-in-script') {
        # What the plugin's "write the agent" does: salt and hash, no PSK.
        $salt = Get-RandomHex 16
        $hash = Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes("$salt`:$($script:psk)"))
        $script = $script.Replace("const AGENT_PSK_SALT = '';", "const AGENT_PSK_SALT = '$salt';").Replace("const AGENT_PSK_SHA256 = '';", "const AGENT_PSK_SHA256 = '$hash';")
    }
    [System.IO.File]::WriteAllText((Join-Path $docroot 'sftp.php'), $script, [Text.UTF8Encoding]::new($false))
    $key = Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes("$salt`:$($script:psk)"))

    $port = Get-FreePort
    $env:TC_SFTP_AGENT_PSK = if ($config -eq 'psk-in-environment') { $script:psk } else { $null }
    $server = Start-Process -FilePath $Php -ArgumentList '-S', "127.0.0.1:$port", '-t', "`"$docroot`"" -PassThru -WindowStyle Hidden
    $env:TC_SFTP_AGENT_PSK = $null
    $base = "http://127.0.0.1:$port/sftp.php"
    try {
        $deadline = (Get-Date).AddSeconds(15)
        do {
            Start-Sleep -Milliseconds 200
            $up = try { (Invoke-WebRequest -Uri "$base`?op=PROBE" -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 2).StatusCode -eq 200 } catch { $false }
        } until ($up -or (Get-Date) -gt $deadline)
        if (-not $up) { throw "PHP's built-in server did not answer on port $port" }

        $before = $script:failed
        Test-Agent $config $base $key $salt
        if ($script:failed -ne $before) { $failedSteps.Add("protocol ($config)") }

        if (-not $SkipIntegration) {
            Write-Host "--- plugin integration ($config)" -ForegroundColor Cyan
            $iniDir = Join-Path ([System.IO.Path]::GetTempPath()) "sftpplug-php-ini-$PID"
            New-Item -ItemType Directory -Path $iniDir -Force | Out-Null
            $ini = Join-Path $iniDir 'sftpplug.ini'
            [System.IO.File]::WriteAllText($ini, "[phpagent]`r`nserver=$base`r`nuser=tester`r`ntransfermode=1`r`npassword=plain:$($script:psk)`r`n")
            & pwsh -NoProfile -File (Join-Path $PSScriptRoot 'run-integration-tests.ps1') -IniPath $ini -Profile phpagent -Modes php -RemoteBase / -Arch $Arch
            if ($LASTEXITCODE -ne 0) { $failedSteps.Add("integration ($config)") }
            Remove-Item -LiteralPath $iniDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    } finally {
        if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force }
        $server.WaitForExit(5000) | Out-Null
        Remove-Item -LiteralPath $docroot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host "protocol checks: $($script:passed) passed, $($script:failed) failed"
if ($failedSteps.Count) {
    Write-Host "PHP AGENT TESTS FAILED: $($failedSteps -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host 'PHP AGENT TESTS PASSED' -ForegroundColor Green
