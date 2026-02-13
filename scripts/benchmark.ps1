param(
    [ValidateSet("scan", "load-test", "smoke")]
    [string]$Mode = "scan",
    [string]$Interface = "",
    [int]$Iterations = 5,
    [int]$Concurrency = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Iterations -le 0) {
    throw "Iterations must be > 0."
}
if ($Concurrency -le 0) {
    throw "Concurrency must be > 0."
}

Write-Host "Building release binary..."
cargo build --release -p nexus-cli | Out-Host

$exe = Join-Path (Get-Location) "target\release\nexus-core.exe"
if (-not (Test-Path $exe)) {
    throw "Release binary not found at $exe"
}

if ($Mode -eq "smoke") {
    Write-Host "Running benchmark smoke checks (no network scan)..."
    $versionOutput = & $exe --version
    $helpOutput = & $exe --help
    $aiCheckOutput = & $exe ai-check 2>$null
    $aiCheckJson = $aiCheckOutput | ConvertFrom-Json
    $summary = [pscustomobject]@{
        mode                 = "smoke"
        version              = $versionOutput
        usage_contains_scan  = ($helpOutput -join "`n") -match "nexus-core \[scan\]"
        ai_check_mode        = [string]$aiCheckJson.mode
        ai_check_overall_ok  = [bool]$aiCheckJson.overall_ok
    }
    $summary | ConvertTo-Json -Depth 6
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Interface)) {
    $interfaces = & $exe interfaces 2>$null
    $Interface = $interfaces | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($Interface)) {
        throw "No valid interface found. Use -Interface to specify one."
    }
}

Write-Host "Interface: $Interface"
Write-Host "Mode: $Mode"

if ($Mode -eq "load-test") {
    $output = & $exe load-test --interface $Interface --iterations $Iterations --concurrency $Concurrency 2>$null
    $json = $output | ConvertFrom-Json
    $json | ConvertTo-Json -Depth 6
    exit 0
}

$rows = @()
for ($i = 1; $i -le $Iterations; $i++) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $output = & $exe scan --interface $Interface 2>$null
    $sw.Stop()

    $scan = $output | ConvertFrom-Json
    $rows += [pscustomobject]@{
        iteration         = $i
        wall_time_ms      = [int64]$sw.ElapsedMilliseconds
        reported_scan_ms  = [int64]$scan.scan_duration_ms
        hosts_found       = [int]$scan.total_hosts
        arp_discovered    = [int]$scan.arp_discovered
        icmp_discovered   = [int]$scan.icmp_discovered
    }
}

$rows | Format-Table -AutoSize | Out-Host

$summary = [pscustomobject]@{
    mode                    = $Mode
    interface               = $Interface
    iterations              = $Iterations
    avg_wall_time_ms        = [math]::Round(($rows | Measure-Object wall_time_ms -Average).Average, 2)
    min_wall_time_ms        = [int64](($rows | Measure-Object wall_time_ms -Minimum).Minimum)
    max_wall_time_ms        = [int64](($rows | Measure-Object wall_time_ms -Maximum).Maximum)
    avg_reported_scan_ms    = [math]::Round(($rows | Measure-Object reported_scan_ms -Average).Average, 2)
    avg_hosts_found         = [math]::Round(($rows | Measure-Object hosts_found -Average).Average, 2)
}

Write-Host "`nSummary:"
$summary | ConvertTo-Json -Depth 6
