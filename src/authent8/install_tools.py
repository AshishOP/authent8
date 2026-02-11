#!/usr/bin/env python3
"""
Authent8 Tool Installer
Automatically installs Authent8 scanner toolchain
"""
import subprocess
import platform
import shutil
import sys
import os
import tempfile
import urllib.request
import tarfile
import zipfile

def run_cmd(cmd, check=True):
    """Run a command and return success status"""
    try:
        subprocess.run(cmd, check=check, shell=False, capture_output=True)
        return True
    except subprocess.SubprocessError:
        return False

def get_pipx_cmd():
    """Best-effort pipx command path."""
    pipx = shutil.which("pipx")
    if pipx:
        return pipx
    local = os.path.join(os.path.expanduser("~"), ".local", "bin", "pipx")
    if os.path.exists(local):
        return local
    return None

def install_with_pipx(package: str, app_hint: str) -> bool:
    """Install a CLI app via pipx."""
    pipx_cmd = get_pipx_cmd()
    if not pipx_cmd:
        print(f"❌ pipx is required to install {app_hint}. Please install pipx first.")
        return False
    try:
        subprocess.run([pipx_cmd, "install", package, "--force"], check=True)
        return True
    except Exception as e:
        print(f"❌ Failed to install {app_hint} via pipx: {e}")
        return False

def get_local_bin():
    """Get the local bin path for authent8 tools"""
    if platform.system().lower() == "windows":
        return os.path.join(os.environ.get("LOCALAPPDATA", ""), "authent8", "bin")
    else:
        return os.path.join(os.path.expanduser("~"), ".local", "bin")

def is_installed(tool):
    """Check if a tool is installed"""
    if shutil.which(tool) is not None:
        return True
    
    local_bin = get_local_bin()
    if platform.system().lower() == "windows":
        local_path = os.path.join(local_bin, f"{tool}.exe")
    else:
        local_path = os.path.join(local_bin, tool)
    
    if os.path.exists(local_path):
        if local_bin not in os.environ.get("PATH", ""):
            os.environ["PATH"] = local_bin + os.pathsep + os.environ.get("PATH", "")
        return True
    
    return False

def install_semgrep():
    """Install semgrep via pipx"""
    print("📦 Installing Semgrep...")
    if install_with_pipx("semgrep", "Semgrep") and is_installed("semgrep"):
        print("✅ Semgrep installed!")
        return True
    print("❌ Semgrep is still not available after installation.")
    return False

def install_bandit():
    """Install Bandit via pipx"""
    print("📦 Installing Bandit...")
    if install_with_pipx("bandit", "Bandit") and is_installed("bandit"):
        print("✅ Bandit installed!")
        return True
    print("❌ Bandit is still not available after installation.")
    return False

def install_detect_secrets():
    """Install detect-secrets via pipx"""
    print("📦 Installing detect-secrets...")
    if install_with_pipx("detect-secrets", "detect-secrets") and is_installed("detect-secrets"):
        print("✅ detect-secrets installed!")
        return True
    print("❌ detect-secrets is still not available after installation.")
    return False

def install_checkov():
    """Install Checkov via pipx"""
    print("📦 Installing Checkov...")
    if install_with_pipx("checkov", "Checkov") and is_installed("checkov"):
        print("✅ Checkov installed!")
        return True
    print("❌ Checkov is still not available after installation.")
    return False

def install_grype():
    """Install Grype using official install script on Unix-like systems."""
    print("📦 Installing Grype...")
    system = platform.system().lower()
    local_bin = get_local_bin()
    os.makedirs(local_bin, exist_ok=True)
    try:
        if system in ("linux", "darwin"):
            cmd = f'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b "{local_bin}"'
            subprocess.run(["sh", "-c", cmd], check=True)
            print(f"✅ Grype installed to {local_bin}!")
            return True
        if system == "windows" and is_installed("choco"):
            if run_cmd(["choco", "install", "grype", "-y"]):
                print("✅ Grype installed via Chocolatey!")
                return True
    except Exception as e:
        print(f"⚠️  Could not auto-install Grype: {e}")
    return False

def install_osv_scanner():
    """Install OSV-Scanner."""
    print("📦 Installing OSV-Scanner...")
    system = platform.system().lower()
    local_bin = get_local_bin()
    os.makedirs(local_bin, exist_ok=True)
    try:
        if system in ("linux", "darwin"):
            # First try Go install if available
            if shutil.which("go"):
                env = os.environ.copy()
                env["GOBIN"] = local_bin
                subprocess.run(
                    ["go", "install", "github.com/google/osv-scanner/cmd/osv-scanner@latest"],
                    check=True,
                    env=env,
                )
                print(f"✅ OSV-Scanner installed via go install to {local_bin}!")
                return True
        # Binary fallback from GitHub release assets.
        with urllib.request.urlopen("https://api.github.com/repos/google/osv-scanner/releases/latest") as resp:
            release_json = resp.read().decode("utf-8", errors="ignore")
        import re
        match = re.search(r'"tag_name"\s*:\s*"([^"]+)"', release_json)
        version = match.group(1) if match else ""
        if version:
            osv_os = "darwin" if system == "darwin" else ("linux" if system == "linux" else "windows")
            machine = platform.machine().lower()
            osv_arch = "arm64" if ("arm64" in machine or "aarch64" in machine) else "amd64"
            candidates = [
                f"osv-scanner_{osv_os}_{osv_arch}",
                f"osv-scanner_{osv_os}_{osv_arch}.tar.gz",
                f"osv-scanner_{osv_os}_{osv_arch}.zip",
            ]
            with tempfile.TemporaryDirectory() as tmpdir:
                for name in candidates:
                    url = f"https://github.com/google/osv-scanner/releases/download/{version}/{name}"
                    dst = os.path.join(tmpdir, name.replace("/", "_"))
                    try:
                        urllib.request.urlretrieve(url, dst)
                    except Exception:
                        continue
                    if name.endswith(".tar.gz"):
                        try:
                            with tarfile.open(dst, "r:gz") as tf:
                                tf.extractall(tmpdir)
                        except Exception:
                            continue
                    elif name.endswith(".zip"):
                        try:
                            with zipfile.ZipFile(dst, "r") as zf:
                                zf.extractall(tmpdir)
                        except Exception:
                            continue
                    else:
                        os.chmod(dst, 0o755)
                        final = os.path.join(local_bin, "osv-scanner.exe" if system == "windows" else "osv-scanner")
                        shutil.copy2(dst, final)
                        if system != "windows":
                            os.chmod(final, 0o755)
                        if is_installed("osv-scanner"):
                            print("✅ OSV-Scanner installed from release binary!")
                            return True

                    extracted = os.path.join(tmpdir, "osv-scanner.exe" if system == "windows" else "osv-scanner")
                    if os.path.exists(extracted):
                        final = os.path.join(local_bin, "osv-scanner.exe" if system == "windows" else "osv-scanner")
                        shutil.copy2(extracted, final)
                        if system != "windows":
                            os.chmod(final, 0o755)
                        if is_installed("osv-scanner"):
                            print("✅ OSV-Scanner installed from release archive!")
                            return True
    except Exception as e:
        print(f"⚠️  Could not auto-install OSV-Scanner: {e}")
    if not is_installed("osv-scanner"):
        print("❌ OSV-Scanner is still not available after installation.")
        return False
    return True

def install_trivy():
    """Install Trivy based on OS"""
    print("📦 Installing Trivy...")
    system = platform.system().lower()
    
    if system == "darwin":  # macOS
        if is_installed("brew"):
            if run_cmd(["brew", "install", "trivy"]):
                print("✅ Trivy installed via Homebrew!")
                return True
    
    elif system == "linux":
        # Try downloading binary
        try:
            arch = platform.machine().lower()
            if "x86_64" in arch or "amd64" in arch:
                arch = "64bit"
            elif "arm64" in arch or "aarch64" in arch:
                arch = "ARM64"
            
            url = f"https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.50.0_Linux-{arch}.tar.gz"
            local_bin = get_local_bin()
            os.makedirs(local_bin, exist_ok=True)
            
            with tempfile.TemporaryDirectory() as tmpdir:
                tarfile = os.path.join(tmpdir, "trivy.tar.gz")
                urllib.request.urlretrieve(url, tarfile)
                subprocess.run(["tar", "-xzf", tarfile, "-C", tmpdir], check=True)
                src = os.path.join(tmpdir, "trivy")
                dst = os.path.join(local_bin, "trivy")
                shutil.copy2(src, dst)
                os.chmod(dst, 0o755)
            print(f"✅ Trivy installed to {local_bin}!")
            return True
        except Exception as e:
            print(f"⚠️  Could not auto-install Trivy: {e}")
    
    elif system == "windows":
        if is_installed("choco"):
            if run_cmd(["choco", "install", "trivy", "-y"]):
                print("✅ Trivy installed via Chocolatey!")
                return True
        
        try:
            import zipfile
            url = "https://github.com/aquasecurity/trivy/releases/download/v0.50.0/trivy_0.50.0_windows-64bit.zip"
            local_bin = get_local_bin()
            os.makedirs(local_bin, exist_ok=True)
            
            with tempfile.TemporaryDirectory() as tmpdir:
                zip_path = os.path.join(tmpdir, "trivy.zip")
                urllib.request.urlretrieve(url, zip_path)
                with zipfile.ZipFile(zip_path, 'r') as z:
                    z.extractall(tmpdir)
                src = os.path.join(tmpdir, "trivy.exe")
                dst = os.path.join(local_bin, "trivy.exe")
                shutil.copy2(src, dst)
            print(f"✅ Trivy installed to {local_bin}")
            return True
        except Exception as e:
            print(f"⚠️  Could not auto-install Trivy: {e}")
    
    return False

def install_gitleaks():
    """Install Gitleaks based on OS"""
    print("📦 Installing Gitleaks...")
    system = platform.system().lower()
    
    if system == "darwin":  # macOS
        if is_installed("brew"):
            if run_cmd(["brew", "install", "gitleaks"]):
                print("✅ Gitleaks installed via Homebrew!")
                return True
    
    elif system == "linux":
        try:
            arch = platform.machine().lower()
            if "x86_64" in arch or "amd64" in arch:
                arch = "x64"
            elif "arm64" in arch or "aarch64" in arch:
                arch = "arm64"
            
            url = f"https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_{arch}.tar.gz"
            local_bin = get_local_bin()
            os.makedirs(local_bin, exist_ok=True)
            
            with tempfile.TemporaryDirectory() as tmpdir:
                tarfile = os.path.join(tmpdir, "gitleaks.tar.gz")
                urllib.request.urlretrieve(url, tarfile)
                subprocess.run(["tar", "-xzf", tarfile, "-C", tmpdir], check=True)
                src = os.path.join(tmpdir, "gitleaks")
                dst = os.path.join(local_bin, "gitleaks")
                shutil.copy2(src, dst)
                os.chmod(dst, 0o755)
            print(f"✅ Gitleaks installed to {local_bin}!")
            return True
        except Exception as e:
            print(f"⚠️  Could not auto-install Gitleaks: {e}")
    
    elif system == "windows":
        if is_installed("choco"):
            if run_cmd(["choco", "install", "gitleaks", "-y"]):
                print("✅ Gitleaks installed via Chocolatey!")
                return True
        
        try:
            import zipfile
            url = "https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_windows_x64.zip"
            local_bin = get_local_bin()
            os.makedirs(local_bin, exist_ok=True)
            
            with tempfile.TemporaryDirectory() as tmpdir:
                zip_path = os.path.join(tmpdir, "gitleaks.zip")
                urllib.request.urlretrieve(url, zip_path)
                with zipfile.ZipFile(zip_path, 'r') as z:
                    z.extractall(tmpdir)
                src = os.path.join(tmpdir, "gitleaks.exe")
                dst = os.path.join(local_bin, "gitleaks.exe")
                shutil.copy2(src, dst)
            print(f"✅ Gitleaks installed to {local_bin}")
            return True
        except Exception as e:
            print(f"⚠️  Could not auto-install Gitleaks: {e}")
            
    return False

def check_and_install():
    """Check for tools and install if missing"""
    print("\n🔧 Authent8 Tool Setup\n")
    print("Checking for required security scanners...\n")
    
    all_ok = True
    
    if is_installed("semgrep"):
        print("✅ Semgrep: installed")
    else:
        if not install_semgrep():
            all_ok = False

    if is_installed("bandit"):
        print("✅ Bandit: installed")
    else:
        if not install_bandit():
            all_ok = False

    if is_installed("detect-secrets"):
        print("✅ detect-secrets: installed")
    else:
        if not install_detect_secrets():
            all_ok = False

    if is_installed("checkov"):
        print("✅ Checkov: installed")
    else:
        if not install_checkov():
            all_ok = False

    if is_installed("grype"):
        print("✅ Grype: installed")
    else:
        if not install_grype():
            all_ok = False

    if is_installed("osv-scanner"):
        print("✅ OSV-Scanner: installed")
    else:
        if not install_osv_scanner():
            all_ok = False
    
    if is_installed("trivy"):
        print("✅ Trivy: installed")
    else:
        if not install_trivy():
            all_ok = False
    
    if is_installed("gitleaks"):
        print("✅ Gitleaks: installed")
    else:
        if not install_gitleaks():
            all_ok = False
    
    print()
    if all_ok:
        print("🎉 All tools ready! Run 'authent8' to start scanning.\n")
    else:
        print("⚠️  Some tools need manual installation.\n")
    
    return all_ok

def main():
    check_and_install()

if __name__ == "__main__":
    main()
