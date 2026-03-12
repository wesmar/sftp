$ErrorActionPreference = "Stop"

$sevenZip = "C:\Program Files\7-Zip\7z.exe"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$srcDir = Join-Path $projectRoot "src"
$buildDir = Join-Path $projectRoot "build"
$docsDir = Join-Path $projectRoot "docs"
$backupRoot = "C:\backup\sftp"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$archivePath = Join-Path $backupRoot ("sftp_src_build_docs_" + $timestamp + ".7z")

if (!(Test-Path $sevenZip)) {
    Write-Error "7-Zip not found: $sevenZip"
    exit 1
}

if (!(Test-Path $srcDir)) {
    Write-Error "Source directory not found: $srcDir"
    exit 1
}
if (!(Test-Path $buildDir)) {
    Write-Error "Build directory not found: $buildDir"
    exit 1
}
if (!(Test-Path $docsDir)) {
    Write-Error "Docs directory not found: $docsDir"
    exit 1
}

if (!(Test-Path $backupRoot)) {
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
}

Write-Host "--- Creating source backup ---" -ForegroundColor Cyan
Write-Host "Source:  $srcDir" -ForegroundColor Gray
Write-Host "Build:   $buildDir" -ForegroundColor Gray
Write-Host "Docs:    $docsDir" -ForegroundColor Gray
Write-Host "Archive: $archivePath" -ForegroundColor Gray

Push-Location $projectRoot
try {
    &$sevenZip a -t7z -mx=9 $archivePath ".\src" ".\build" ".\docs" | Out-Null
} finally {
    Pop-Location
}

if (!(Test-Path $archivePath)) {
    Write-Error "Backup failed: archive was not created."
    exit 1
}

$info = Get-Item $archivePath
Write-Host "Backup created:" -ForegroundColor Green
Write-Host ("  " + $info.FullName) -ForegroundColor Gray
Write-Host ("  Size: " + [Math]::Round($info.Length / 1MB, 2) + " MB") -ForegroundColor Gray
