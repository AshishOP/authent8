# Authent8 Installer for Windows
# Usage: irm https://raw.githubusercontent.com/AshishOP/authent8/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

# Colors
function Write-Blue { param($msg) Write-Host $msg -ForegroundColor Blue }
function Write-Green { param($msg) Write-Host $msg -ForegroundColor Green }
function Write-Yellow { param($msg) Write-Host $msg -ForegroundColor Yellow }
function Write-Red { param($msg) Write-Host $msg -ForegroundColor Red }

# Banner
Write-Blue @"

  █████  ██   ██ ████████ ██  ██ ███████ ███   ██ ████████  █████ 
 ██   ██ ██   ██    ██    ██  ██ ██      ████  ██    ██    ██   ██
 ███████ ██   ██    ██    ██████ █████   ██ ██ ██    ██     █████ 
 ██   ██ ██   ██    ██    ██  ██ ██      ██  ████    ██    ██   ██
 ██   ██  █████     ██    ██  ██ ███████ ██   ███    ██     █████ 

"@
Write-Green "Privacy-First Security Scanner"
Write-Host ""

# Check for winget
Write-Blue "[1/5] Checking package manager..."
$hasWinget = Get-Command winget -ErrorAction SilentlyContinue
$hasChoco = Get-Command choco -ErrorAction SilentlyContinue
$hasScoop = Get-Command scoop -ErrorAction SilentlyContinue

if ($hasWinget) {
    Write-Host "       " -NoNewline; Write-Green "✓ winget found"
    $pkgManager = "winget"
} elseif ($hasChoco) {
    Write-Host "       " -NoNewline; Write-Green "✓ chocolatey found"
    $pkgManager = "choco"
} elseif ($hasScoop) {
    Write-Host "       " -NoNewline; Write-Green "✓ scoop found"
    $pkgManager = "scoop"
} else {
    Write-Yellow "       → No package manager found. Will use pip directly."
    $pkgManager = "none"
}

# Check Python
Write-Blue "[2/5] Checking Python..."
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    $python = Get-Command python3 -ErrorAction SilentlyContinue
}

if ($python) {
    $version = python --version 2>&1
    Write-Host "       " -NoNewline; Write-Green "✓ $version found"
} else {
    Write-Host "       " -NoNewline; Write-Red "✗ Python not found. Installing..."
    if ($pkgManager -eq "winget") {
        winget install Python.Python.3.11 --silent
    } elseif ($pkgManager -eq "choco") {
        choco install python -y
    } elseif ($pkgManager -eq "scoop") {
        scoop install python
    } else {
        Write-Red "Please install Python from https://python.org"
        exit 1
    }
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

# Check pip
Write-Blue "[3/5] Checking pip..."
try {
    python -m pip --version | Out-Null
    Write-Host "       " -NoNewline; Write-Green "✓ pip ready"
} catch {
    Write-Host "       " -NoNewline; Write-Yellow "→ Installing pip..."
    python -m ensurepip --upgrade
}

# Install Authent8
Write-Blue "[4/5] Installing Authent8..."
Write-Host "       " -NoNewline; Write-Yellow "→ Installing/Updating from GitHub..."
python -m pip install --user --upgrade --force-reinstall git+https://github.com/AshishOP/authent8.git --quiet
Write-Host "       " -NoNewline; Write-Green "✓ Authent8 installed"

# Add Python Scripts to PATH
$pythonScripts = python -c "import site; print(site.USER_SITE.replace('site-packages', 'Scripts'))"
if ($env:Path -notlike "*$pythonScripts*") {
    [Environment]::SetEnvironmentVariable("Path", $env:Path + ";$pythonScripts", [EnvironmentVariableTarget]::User)
    $env:Path = $env:Path + ";$pythonScripts"
}

# Install security tools
Write-Blue "[5/5] Installing security scanners..."

# Trivy
$trivy = Get-Command trivy -ErrorAction SilentlyContinue
if (-not $trivy) {
    Write-Host "       " -NoNewline; Write-Yellow "→ Installing Trivy..."
    if ($pkgManager -eq "winget") {
        winget install AquaSecurity.Trivy --silent
    } elseif ($pkgManager -eq "choco") {
        choco install trivy -y
    } elseif ($pkgManager -eq "scoop") {
        scoop bucket add extras
        scoop install trivy
    } else {
        Write-Yellow "       Please install Trivy manually from: https://github.com/aquasecurity/trivy/releases"
    }
}
Write-Host "       " -NoNewline; Write-Green "✓ Trivy ready"

# Semgrep
$semgrep = Get-Command semgrep -ErrorAction SilentlyContinue
if (-not $semgrep) {
    Write-Host "       " -NoNewline; Write-Yellow "→ Installing Semgrep..."
    python -m pip install --user semgrep --quiet
}
Write-Host "       " -NoNewline; Write-Green "✓ Semgrep ready"

# Gitleaks
$gitleaks = Get-Command gitleaks -ErrorAction SilentlyContinue
if (-not $gitleaks) {
    Write-Host "       " -NoNewline; Write-Yellow "→ Installing Gitleaks..."
    if ($pkgManager -eq "winget") {
        winget install Gitleaks.Gitleaks --silent
    } elseif ($pkgManager -eq "choco") {
        choco install gitleaks -y
    } elseif ($pkgManager -eq "scoop") {
        scoop install gitleaks
    } else {
        Write-Yellow "       Please install Gitleaks manually from: https://github.com/gitleaks/gitleaks/releases"
    }
}
Write-Host "       " -NoNewline; Write-Green "✓ Gitleaks ready"

Write-Host ""
Write-Green "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Green "✓ Installation complete!"
Write-Green "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host ""
Write-Host "Run " -NoNewline; Write-Blue "authent8" -NoNewline; Write-Host " to start scanning!"
Write-Yellow "💡 Pro Tip: Stop managing environment variables manually!"
Write-Host "   Run " -NoNewline; Write-Blue "authent8" -NoNewline; Write-Host " and go to " -NoNewline; Write-Blue "⚙ Configuration" -NoNewline; Write-Host " to set up your AI key interactively."
Write-Host ""

# Note about restart
Write-Yellow "Note: You may need to restart your terminal for PATH changes to take effect."
