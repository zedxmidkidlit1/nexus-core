param(
    [switch]$SkipBuild,
    [switch]$Clean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

$distDir = Join-Path $repoRoot "dist"
$releaseExe = Join-Path $repoRoot "target\release\nexus-core.exe"

if ($Clean -and (Test-Path $distDir)) {
    Remove-Item -Path $distDir -Recurse -Force
}

if (-not $SkipBuild) {
    Write-Host "Building release binary..."
    cargo build --release | Out-Host
}

if (-not (Test-Path $releaseExe)) {
    throw "Release binary not found at $releaseExe. Run 'cargo build --release' first."
}

New-Item -Path $distDir -ItemType Directory -Force | Out-Null

Write-Host "Copying binary and docs to dist..."
Copy-Item -Path $releaseExe -Destination (Join-Path $distDir "nexus-core.exe") -Force
$windowsRunner = Join-Path $repoRoot "scripts\run-nexus.cmd"
if (Test-Path $windowsRunner) {
    Copy-Item -Path $windowsRunner -Destination (Join-Path $distDir "run-nexus.cmd") -Force
}

$docsToCopy = @(
    "README.md",
    "PROJECTCONTEXT.md",
    ".env.example"
)

foreach ($doc in $docsToCopy) {
    $source = Join-Path $repoRoot $doc
    if (Test-Path $source) {
        Copy-Item -Path $source -Destination (Join-Path $distDir $doc) -Force
    }
}

$commit = (git rev-parse --short HEAD 2>$null)
$versionOutput = (& $releaseExe --version 2>$null)
$manifest = [pscustomobject]@{
    packaged_at_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    git_commit      = if ($LASTEXITCODE -eq 0) { $commit } else { $null }
    binary_version  = if ($versionOutput) { $versionOutput } else { $null }
    files           = (Get-ChildItem -Path $distDir -File | Select-Object -ExpandProperty Name | Sort-Object)
}

$manifest | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $distDir "package_manifest.json") -Encoding UTF8

Write-Host "Package ready: $distDir"
Get-ChildItem -Path $distDir -File | Select-Object Name, Length
