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

def run_cmd(cmd, check=True, shell=False):
    """Run a command and return success status"""
    try:
        subprocess.run(cmd, check=check, shell=shell, capture_output=True)
        return True
    except:
        return False

def is_installed(tool):
    """Check if a tool is installed"""
    return shutil.which(tool) is not None

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
        # Try apt first
        if is_installed("apt-get"):
            try:
                cmds = [
                    "sudo apt-get update -qq",
                    "sudo apt-get install -y wget apt-transport-https gnupg lsb-release -qq",
                    "wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -",
                    'echo "deb https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list',
                    "sudo apt-get update -qq",
                    "sudo apt-get install -y trivy -qq"
                ]
                for cmd in cmds:
                    subprocess.run(cmd, shell=True, check=True, capture_output=True)
                print("✅ Trivy installed via apt!")
                return True
            except:
                pass
        
        # Try downloading binary
        try:
            arch = platform.machine()
            if arch == "x86_64":
                arch = "64bit"
            elif arch == "aarch64":
                arch = "ARM64"
            
            url = f"https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.50.0_Linux-{arch}.tar.gz"
            with tempfile.TemporaryDirectory() as tmpdir:
                tarfile = os.path.join(tmpdir, "trivy.tar.gz")
                urllib.request.urlretrieve(url, tarfile)
                subprocess.run(["tar", "-xzf", tarfile, "-C", tmpdir], check=True)
                subprocess.run(["sudo", "mv", os.path.join(tmpdir, "trivy"), "/usr/local/bin/"], check=True)
            print("✅ Trivy installed!")
            return True
        except Exception as e:
            print(f"⚠️  Could not auto-install Trivy: {e}")
    
    elif system == "windows":
        # Try Chocolatey first
        if is_installed("choco"):
            if run_cmd(["choco", "install", "trivy", "-y"]):
                print("✅ Trivy installed via Chocolatey!")
                return True
        
        # Download binary directly
        try:
            import zipfile
            url = "https://github.com/aquasecurity/trivy/releases/download/v0.50.0/trivy_0.50.0_windows-64bit.zip"
            local_bin = os.path.join(os.environ.get("LOCALAPPDATA", ""), "authent8", "bin")
            os.makedirs(local_bin, exist_ok=True)
            
            with tempfile.TemporaryDirectory() as tmpdir:
                zip_path = os.path.join(tmpdir, "trivy.zip")
                print("   Downloading Trivy...")
                urllib.request.urlretrieve(url, zip_path)
                
                with zipfile.ZipFile(zip_path, 'r') as z:
                    z.extractall(tmpdir)
                
                # Move to local bin
                src = os.path.join(tmpdir, "trivy.exe")
                dst = os.path.join(local_bin, "trivy.exe")
                shutil.copy2(src, dst)
                
                # Add to PATH for this session
                os.environ["PATH"] = local_bin + os.pathsep + os.environ.get("PATH", "")
                
                print(f"✅ Trivy installed to {local_bin}")
                print(f"   Add this to your PATH: {local_bin}")
                return True
        except Exception as e:
            print(f"⚠️  Could not auto-install Trivy: {e}")
    
    print("❌ Please install Trivy manually: https://trivy.dev/latest/getting-started/installation/")
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
            arch = platform.machine()
            if arch == "x86_64":
                arch = "x64"
            elif arch == "aarch64":
                arch = "arm64"
            
            url = f"https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_{arch}.tar.gz"
            with tempfile.TemporaryDirectory() as tmpdir:
                tarfile = os.path.join(tmpdir, "gitleaks.tar.gz")
                urllib.request.urlretrieve(url, tarfile)
                subprocess.run(["tar", "-xzf", tarfile, "-C", tmpdir], check=True)
                subprocess.run(["sudo", "mv", os.path.join(tmpdir, "gitleaks"), "/usr/local/bin/"], check=True)
            print("✅ Gitleaks installed!")
            return True
        except Exception as e:
            print(f"⚠️  Could not auto-install Gitleaks: {e}")
    
    elif system == "windows":
        # Try Chocolatey first
        if is_installed("choco"):
            if run_cmd(["choco", "install", "gitleaks", "-y"]):
                print("✅ Gitleaks installed via Chocolatey!")
                return True
        
        # Download binary directly
        try:
            import zipfile
            url = "https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_windows_x64.zip"
            local_bin = os.path.join(os.environ.get("LOCALAPPDATA", ""), "authent8", "bin")
            os.makedirs(local_bin, exist_ok=True)
            
            with tempfile.TemporaryDirectory() as tmpdir:
                zip_path = os.path.join(tmpdir, "gitleaks.zip")
                print("   Downloading Gitleaks...")
                urllib.request.urlretrieve(url, zip_path)
                
                with zipfile.ZipFile(zip_path, 'r') as z:
                    z.extractall(tmpdir)
                
                # Move to local bin
                src = os.path.join(tmpdir, "gitleaks.exe")
                dst = os.path.join(local_bin, "gitleaks.exe")
                shutil.copy2(src, dst)
                
                # Add to PATH for this session
                os.environ["PATH"] = local_bin + os.pathsep + os.environ.get("PATH", "")
                
                print(f"✅ Gitleaks installed to {local_bin}")
                return True
        except Exception as e:
            print(f"⚠️  Could not auto-install Gitleaks: {e}")
    
    print("❌ Please install Gitleaks manually: https://github.com/gitleaks/gitleaks/releases")
    return False

def check_and_install():
    """Check for tools and install if missing"""
    print("\n🔧 Authent8 Tool Setup\n")
    print("Checking for required security scanners...\n")
    
    all_ok = True
    
    # Check Semgrep
    if is_installed("semgrep"):
        print("✅ Semgrep: installed")
    else:
        if not install_semgrep():
            all_ok = False
    
    # Check Trivy  
    if is_installed("trivy"):
        print("✅ Trivy: installed")
    else:
        if not install_trivy():
            all_ok = False
    
    # Check Gitleaks
    if is_installed("gitleaks"):
        print("✅ Gitleaks: installed")
    else:
        if not install_gitleaks():
            all_ok = False
    
    print()
    if all_ok:
        print("🎉 All tools ready! Run 'authent8' to start scanning.\n")
    else:
        print("⚠️  Some tools need manual installation. Authent8 will work")
        print("   but skip unavailable scanners. See INSTALL.md for help.\n")
    
    return all_ok

def main():
    """CLI entry point"""
    check_and_install()

if __name__ == "__main__":
    main()
