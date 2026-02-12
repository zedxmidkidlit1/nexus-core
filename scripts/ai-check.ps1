param(
    [ValidateSet("local", "cloud", "hybrid_auto")]
    [string]$Mode = "local",
    [string]$OllamaModel = "qwen3:8b",
    [string]$GeminiModel = "gemini-2.5-flash",
    [string]$OllamaEndpoint = "http://127.0.0.1:11434",
    [string]$GeminiEndpoint = "https://generativelanguage.googleapis.com",
    [string]$GeminiApiKey = "",
    [int]$TimeoutMs = 8000,
    [switch]$AllowSensitiveCloudPayload
)

$ErrorActionPreference = "Stop"

$env:NEXUS_AI_ENABLED = "true"
$env:NEXUS_AI_MODE = $Mode
$env:NEXUS_AI_TIMEOUT_MS = "$TimeoutMs"
$env:NEXUS_AI_ENDPOINT = $OllamaEndpoint
$env:NEXUS_AI_MODEL = $OllamaModel
$env:NEXUS_AI_GEMINI_ENDPOINT = $GeminiEndpoint
$env:NEXUS_AI_GEMINI_MODEL = $GeminiModel
$env:NEXUS_AI_GEMINI_API_KEY = $GeminiApiKey
$env:NEXUS_AI_CLOUD_ALLOW_SENSITIVE = if ($AllowSensitiveCloudPayload) { "true" } else { "false" }

Write-Host ("Running ai-check with mode='{0}'..." -f $Mode) -ForegroundColor Cyan
if ($Mode -ne "local" -and [string]::IsNullOrWhiteSpace($GeminiApiKey)) {
    Write-Host "Warning: Gemini mode selected but -GeminiApiKey is empty." -ForegroundColor Yellow
}

cargo run -- ai-check
