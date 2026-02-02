#!/usr/bin/env python3
"""
Authent8 Tool Installer
Automatically installs Trivy, Semgrep, and Gitleaks
"""
import subprocess
import platform
import shutil
import sys
import os
import tempfile
import urllib.request

def run_cmd(cmd, check=True):
    """Run a command and return success status"""
    try:
        subprocess.run(cmd, check=check, shell=False, capture_output=True)
        return True
    except subprocess.SubprocessError:
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
    """Install semgrep via pip"""
    print("📦 Installing Semgrep...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "semgrep", "-q"], check=True)
        print("✅ Semgrep installed!")
        return True
    except Exception as e:
        print(f"❌ Failed to install Semgrep: {e}")
        return False

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
