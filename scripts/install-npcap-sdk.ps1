Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Add-CandidateUrl {
    param(
        [System.Collections.Generic.List[string]]$List,
        [string]$Url
    )
    if (-not [string]::IsNullOrWhiteSpace($Url) -and -not $List.Contains($Url)) {
        $List.Add($Url)
    }
}

function Select-BestPacketLib {
    param(
        [System.IO.FileInfo[]]$Candidates
    )
    if (-not $Candidates -or $Candidates.Count -eq 0) {
        return $null
    }

    $scored = foreach ($candidate in $Candidates) {
        $path = $candidate.FullName.ToLowerInvariant()
        $score =
            if ($path -match '\\lib\\x64\\packet\.lib$') { 0 }
            elseif ($path -match '\\lib\\amd64\\packet\.lib$') { 1 }
            elseif ($path -match '\\x64\\packet\.lib$') { 2 }
            elseif ($path -match '\\lib\\packet\.lib$') { 3 }
            else { 4 }

        $hasWpcap = Test-Path (Join-Path $candidate.Directory.FullName "wpcap.lib")
        [pscustomobject]@{
            Candidate = $candidate
            Score = $score
            HasWpcap = $hasWpcap
            PathLength = $candidate.FullName.Length
        }
    }

    # Prefer x64-like paths, then directories that also contain wpcap.lib.
    return ($scored |
        Sort-Object -Property Score, @{ Expression = { if ($_.HasWpcap) { 0 } else { 1 } } }, PathLength |
        Select-Object -First 1).Candidate
}

$candidateUrls = [System.Collections.Generic.List[string]]::new()

# Discover current SDK links from official pages first.
try {
    $home = Invoke-WebRequest -Uri "https://npcap.com/" -UseBasicParsing
    foreach ($m in [regex]::Matches($home.Content, 'https://npcap\.com/dist/npcap-sdk-[0-9.]+\.zip')) {
        Add-CandidateUrl -List $candidateUrls -Url $m.Value
    }
} catch {
    Write-Host "Npcap homepage discovery failed: $($_.Exception.Message)"
}

try {
    $distIndex = Invoke-WebRequest -Uri "https://npcap.com/dist/" -UseBasicParsing
    foreach ($m in [regex]::Matches($distIndex.Content, 'npcap-sdk-[0-9.]+\.zip')) {
        Add-CandidateUrl -List $candidateUrls -Url ("https://npcap.com/dist/{0}" -f $m.Value)
    }
} catch {
    Write-Host "Npcap dist index discovery failed: $($_.Exception.Message)"
}

# Fallbacks for transient parsing/site changes.
$fallbacks = @(
    "https://npcap.com/dist/npcap-sdk-1.16.zip",
    "https://npcap.com/dist/npcap-sdk-1.15.zip",
    "https://npcap.com/dist/npcap-sdk-1.14.zip"
)
foreach ($url in $fallbacks) {
    Add-CandidateUrl -List $candidateUrls -Url $url
}

if ($candidateUrls.Count -eq 0) {
    throw "No Npcap SDK candidate URLs were discovered."
}

$tmpRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
$zipPath = Join-Path $tmpRoot "npcap-sdk.zip"
$extractRoot = Join-Path $tmpRoot "npcap-sdk-extract"

$downloaded = $false
foreach ($url in $candidateUrls) {
    try {
        Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
        Write-Host "Downloaded Npcap SDK from $url"
        $downloaded = $true
        break
    } catch {
        Write-Host "Failed to download from $url"
    }
}

if (-not $downloaded) {
    throw "Failed to download Npcap SDK from discovered/known URLs."
}

if (Test-Path $extractRoot) {
    Remove-Item -Path $extractRoot -Recurse -Force
}
New-Item -Path $extractRoot -ItemType Directory | Out-Null
Expand-Archive -Path $zipPath -DestinationPath $extractRoot -Force

$packetLibCandidates = @(Get-ChildItem -Path $extractRoot -Recurse -Filter "Packet.lib" -ErrorAction SilentlyContinue)
$packetLib = Select-BestPacketLib -Candidates $packetLibCandidates

if (-not $packetLib) {
    $knownPacketLibPaths = @(
        "C:\\npcap-sdk\\Lib\\x64\\Packet.lib",
        "C:\\Program Files\\Npcap\\SDK\\Lib\\x64\\Packet.lib",
        "C:\\npcap-sdk\\Lib\\Packet.lib",
        "C:\\Program Files\\Npcap\\SDK\\Lib\\Packet.lib"
    )
    foreach ($knownPath in $knownPacketLibPaths) {
        if (Test-Path $knownPath) {
            $packetLib = Get-Item $knownPath
            break
        }
    }
}

if (-not $packetLib) {
    Write-Host "DEBUG: discovered Packet.lib candidates:"
    if ($packetLibCandidates.Count -gt 0) {
        foreach ($candidate in $packetLibCandidates) {
            Write-Host " - $($candidate.FullName)"
        }
    } else {
        Write-Host " - none"
    }
    throw "Packet.lib not found after Npcap SDK extraction. Checked: $extractRoot"
}

$libDir = $packetLib.Directory.FullName

if ($env:GITHUB_ENV) {
    "LIB=$libDir;$env:LIB" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
    "NPCAP_SDK_LIB=$libDir" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
} else {
    $env:LIB = "$libDir;$env:LIB"
    $env:NPCAP_SDK_LIB = $libDir
}

Write-Host "Configured Packet.lib search path: $libDir"
