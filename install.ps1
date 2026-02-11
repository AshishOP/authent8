# Authent8 Installer for Windows
# Usage: irm https://raw.githubusercontent.com/AshishOP/authent8/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

# Colors
function Write-Blue { param($msg) Write-Host $msg -ForegroundColor Blue }
function Write-Green { param($msg) Write-Host $msg -ForegroundColor Green }
function Write-Yellow { param($msg) Write-Host $msg -ForegroundColor Yellow }
function Write-Red { param($msg) Write-Host $msg -ForegroundColor Red }
$FailedTools = New-Object System.Collections.Generic.List[string]

function Test-ToolReady {
    param([string]$Tool)
    return [bool](Get-Command $Tool -ErrorAction SilentlyContinue)
}

function Mark-ToolFailed {
    param([string]$Tool)
    $FailedTools.Add($Tool) | Out-Null
}

function Ensure-Pipx {
    if (-not (Get-Command pipx -ErrorAction SilentlyContinue)) {
        python -m pip install --user pipx --quiet
        python -m pipx ensurepath | Out-Null
        $userBase = python -c "import site; print(site.USER_BASE)"
        $scripts = Join-Path $userBase "Scripts"
        if ($env:Path -notlike "*$scripts*") { $env:Path = "$scripts;$env:Path" }
    }
}

function Install-OsvScanner {
    # 1) already installed
    if (Test-ToolReady "osv-scanner") { return $true }

    # 2) go install (works on many dev setups)
    if (Get-Command go -ErrorAction SilentlyContinue) {
        try {
            $userBase = python -c "import site; print(site.USER_BASE)"
            $goBin = Join-Path $userBase "bin"
            $env:GOBIN = $goBin
            go install github.com/google/osv-scanner/cmd/osv-scanner@latest | Out-Null
            if ($env:Path -notlike "*$goBin*") { $env:Path = "$goBin;$env:Path" }
            if (Test-ToolReady "osv-scanner") { return $true }
        } catch {}
    }

    # 3) release binary fallback
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/google/osv-scanner/releases/latest"
        $tag = $release.tag_name
        $archRaw = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLower()
        $arch = if ($archRaw -match "arm64") { "arm64" } else { "amd64" }
        $tmp = Join-Path $env:TEMP "osv-scanner.zip"
        $url = "https://github.com/google/osv-scanner/releases/download/$tag/osv-scanner_windows_$arch.zip"
        Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
        $extract = Join-Path $env:TEMP "osv-scanner-extract"
        if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
        Expand-Archive -Path $tmp -DestinationPath $extract -Force
        $exe = Join-Path $extract "osv-scanner.exe"
        if (Test-Path $exe) {
            $userBase = python -c "import site; print(site.USER_BASE)"
            $scripts = Join-Path $userBase "Scripts"
            if (!(Test-Path $scripts)) { New-Item -ItemType Directory -Path $scripts | Out-Null }
            Copy-Item $exe (Join-Path $scripts "osv-scanner.exe") -Force
            if ($env:Path -notlike "*$scripts*") { $env:Path = "$scripts;$env:Path" }
            if (Test-ToolReady "osv-scanner") { return $true }
        }
    } catch {}

    # 4) pipx fallback (may work if package exists in index)
    try {
        pipx install osv-scanner --force | Out-Null
        if (Test-ToolReady "osv-scanner") { return $true }
    } catch {}

    return $false
}

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
Ensure-Pipx

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
    pipx install semgrep --force | Out-Null
}
if (Test-ToolReady "semgrep") {
    Write-Host "       " -NoNewline; Write-Green "✓ Semgrep ready"
} else {
    Write-Host "       " -NoNewline; Write-Red "✗ Semgrep installation failed"
    Mark-ToolFailed "semgrep"
}

# Bandit
$bandit = Get-Command bandit -ErrorAction SilentlyContinue
if (-not $bandit) {
    Write-Host "       " -NoNewline; Write-Yellow "→ Installing Bandit..."
    pipx install bandit --force | Out-Null
}
if (Test-ToolReady "bandit") {
    Write-Host "       " -NoNewline; Write-Green "✓ Bandit ready"
} else {
    Write-Host "       " -NoNewline; Write-Red "✗ Bandit installation failed"
    Mark-ToolFailed "bandit"
}

# detect-secrets
$detectSecrets = Get-Command detect-secrets -ErrorAction SilentlyContinue
if (-not $detectSecrets) {
    Write-Host "       " -NoNewline; Write-Yellow "→ Installing detect-secrets..."
    pipx install detect-secrets --force | Out-Null
}
if (Test-ToolReady "detect-secrets") {
    Write-Host "       " -NoNewline; Write-Green "✓ detect-secrets ready"
} else {
    Write-Host "       " -NoNewline; Write-Red "✗ detect-secrets installation failed"
    Mark-ToolFailed "detect-secrets"
}

# Checkov
$checkov = Get-Command checkov -ErrorAction SilentlyContinue
if (-not $checkov) {
    Write-Host "       " -NoNewline; Write-Yellow "→ Installing Checkov..."
    pipx install checkov --force | Out-Null
}
if (Test-ToolReady "checkov") {
    Write-Host "       " -NoNewline; Write-Green "✓ Checkov ready"
} else {
    Write-Host "       " -NoNewline; Write-Red "✗ Checkov installation failed"
    Mark-ToolFailed "checkov"
}

# Grype
$grype = Get-Command grype -ErrorAction SilentlyContinue
if (-not $grype -and $pkgManager -eq "choco") {
    Write-Host "       " -NoNewline; Write-Yellow "→ Installing Grype..."
    choco install grype -y
}
if (Test-ToolReady "grype") {
    Write-Host "       " -NoNewline; Write-Green "✓ Grype ready"
} else {
    Write-Host "       " -NoNewline; Write-Yellow "⚠ Grype not installed (optional unless SCA scan enabled)"
    Mark-ToolFailed "grype"
}

# OSV-Scanner
$osv = Get-Command osv-scanner -ErrorAction SilentlyContinue
if (-not $osv) {
    Write-Host "       " -NoNewline; Write-Yellow "→ Installing OSV-Scanner..."
    $ok = Install-OsvScanner
} else {
    $ok = $true
}
if ($ok -and (Test-ToolReady "osv-scanner")) {
    Write-Host "       " -NoNewline; Write-Green "✓ OSV-Scanner ready"
} else {
    Write-Host "       " -NoNewline; Write-Red "✗ OSV-Scanner installation failed"
    Mark-ToolFailed "osv-scanner"
}

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
if ($FailedTools.Count -eq 0) {
    Write-Green "✓ Installation complete!"
} else {
    Write-Yellow "⚠ Installation complete with issues."
    Write-Yellow ("  Failed tools: " + ($FailedTools -join ", "))
}
Write-Green "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host ""
Write-Host "Run " -NoNewline; Write-Blue "authent8" -NoNewline; Write-Host " to start scanning!"
Write-Yellow "💡 Pro Tip: Stop managing environment variables manually!"
Write-Host "   Run " -NoNewline; Write-Blue "authent8" -NoNewline; Write-Host " and go to " -NoNewline; Write-Blue "⚙ Configuration" -NoNewline; Write-Host " to set up your AI key interactively."
Write-Host ""

# Note about restart
Write-Yellow "Note: You may need to restart your terminal for PATH changes to take effect."
