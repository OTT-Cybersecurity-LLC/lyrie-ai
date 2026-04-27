# Lyrie Agent — Windows PowerShell installer
# Usage: irm https://lyrie.ai/install.ps1 | iex
# Mirrors the curl-based scripts/install.sh for non-Windows platforms.

[CmdletBinding()]
param(
  [string]$InstallDir = (Join-Path $env:USERPROFILE ".lyrie"),
  [switch]$Quiet
)

$ErrorActionPreference = "Stop"

function Write-Info([string]$msg) { if (-not $Quiet) { Write-Host "  $msg" -ForegroundColor Cyan } }
function Write-Ok  ([string]$msg) { if (-not $Quiet) { Write-Host "✓ $msg" -ForegroundColor Green } }
function Write-Warn([string]$msg) {                    Write-Host "⚠ $msg" -ForegroundColor Yellow }
function Write-Err ([string]$msg) {                    Write-Host "✗ $msg" -ForegroundColor Red    }

if (-not $Quiet) {
  Write-Host ""
  Write-Host "🛡️  Lyrie Agent — Windows installer" -ForegroundColor Cyan
  Write-Host ""
}

# Required tooling
foreach ($tool in @("git", "node")) {
  if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
    Write-Err "$tool is required but was not found in PATH."
    Write-Warn "Install via winget: winget install Git.Git OpenJS.NodeJS.LTS"
    exit 1
  }
}

# Bun (preferred) — install if missing
if (-not (Get-Command bun -ErrorAction SilentlyContinue)) {
  Write-Info "Bun not found; installing (powershell -c \"irm bun.sh/install.ps1 | iex\")"
  try { irm bun.sh/install.ps1 | iex } catch { Write-Warn "Bun install failed; falling back to npm." }
}

if (Test-Path $InstallDir) {
  Write-Info "Updating existing install at $InstallDir"
  Push-Location $InstallDir
  git pull
  Pop-Location
} else {
  Write-Info "Cloning Lyrie Agent into $InstallDir"
  git clone https://github.com/overthetopseo/lyrie-agent.git $InstallDir
}

Push-Location $InstallDir
try {
  if (Get-Command bun -ErrorAction SilentlyContinue) {
    Write-Info "bun install"
    bun install
  } elseif (Get-Command pnpm -ErrorAction SilentlyContinue) {
    pnpm install
  } else {
    npm install
  }
  Write-Ok "Lyrie Agent installed at $InstallDir"
} finally {
  Pop-Location
}

if (-not $Quiet) {
  Write-Host ""
  Write-Host "Start Lyrie:"            -ForegroundColor White
  Write-Host "  cd `"$InstallDir`""     -ForegroundColor Gray
  Write-Host "  bun start"              -ForegroundColor Gray
  Write-Host ""
  Write-Host "Run self-diagnostic:"     -ForegroundColor White
  Write-Host "  bun run scripts/doctor.ts" -ForegroundColor Gray
  Write-Host ""
  Write-Host "Docs: https://docs.lyrie.ai" -ForegroundColor Cyan
  Write-Host ""
}
