#!/usr/bin/env python3
"""
Authent8 CLI - Privacy-First Security Scanner
Main entry point for pip-installed package
"""
import click
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TaskProgressColumn
from rich.panel import Panel
from rich import box
from rich.prompt import Prompt, Confirm
from rich.layout import Layout
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from authent8.core.scanner_orchestrator import ScanOrchestrator
from authent8.core.ai_validator import AIValidator
from authent8.install_tools import check_and_install, is_installed
from authent8 import __version__

console = Console()

# ═══════════════════════════════════════════════════════════════════════════════
# SCAN HISTORY
# ═══════════════════════════════════════════════════════════════════════════════

HISTORY_FILE = Path.home() / ".authent8_history.json"
MAX_HISTORY = 10

def load_scan_history() -> list:
    """Load scan history from file"""
    try:
        if HISTORY_FILE.exists():
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return []

def save_scan_history(history: list):
    """Save scan history to file"""
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history[-MAX_HISTORY:], f, indent=2)
    except:
        pass

def add_to_history(path: str, findings_count: int, critical: int, high: int, duration: float):
    """Add a scan to history"""
    history = load_scan_history()
    history.append({
        "path": path,
        "timestamp": datetime.now().isoformat(),
        "findings": findings_count,
        "critical": critical,
        "high": high,
        "duration": round(duration, 1)
    })
    save_scan_history(history)

def get_recent_scans(limit: int = 3) -> list:
    """Get most recent scans"""
    history = load_scan_history()
    return history[-limit:][::-1]  # Reverse to show newest first

# ═══════════════════════════════════════════════════════════════════════════════
# FIRST-RUN TOOL CHECK
# ═══════════════════════════════════════════════════════════════════════════════

def check_first_run():
    """Check if this is first run and install tools if needed"""
    marker_file = Path.home() / ".authent8_installed"
    
    # Check if tools are missing
    tools_missing = not (is_installed("trivy") and is_installed("semgrep") and is_installed("gitleaks"))
    
    if tools_missing and not marker_file.exists():
        console.print()
        console.print(Panel(
            "[bold yellow]🔧 First-time setup detected![/bold yellow]\n\n"
            "Authent8 needs some security tools to scan your code.\n"
            "We'll try to install them automatically.",
            title="[bold]Welcome to Authent8[/bold]",
            border_style="yellow"
        ))
        console.print()
        
        from rich.prompt import Confirm
        if Confirm.ask("[cyan]Install required tools now?[/cyan]", default=True):
            check_and_install()
            # Create marker file
            marker_file.touch()
        else:
            console.print("[yellow]Skipped. Run 'authent8-setup' later to install tools.[/yellow]")
            console.print()
    elif tools_missing:
        # Show quick warning
        missing = []
        if not is_installed("trivy"): missing.append("trivy")
        if not is_installed("semgrep"): missing.append("semgrep")
        if not is_installed("gitleaks"): missing.append("gitleaks")
        
        if missing:
            console.print(f"[dim]⚠ Missing tools: {', '.join(missing)}. Run 'authent8-setup' to install.[/dim]")

# ═══════════════════════════════════════════════════════════════════════════════
# ENHANCED UI COMPONENTS
# ═══════════════════════════════════════════════════════════════════════════════

def clear_screen():
    """Clear terminal screen"""
    os.system('clear' if os.name != 'nt' else 'cls')

def get_gradient_banner():
    """Create a sleek gradient-style ASCII banner"""
    # Compact, modern banner
    banner = """
[bold bright_cyan]    ╭──────────────────────────────────────────────────────────────╮[/bold bright_cyan]
[bold bright_cyan]    │[/bold bright_cyan]                                                              [bold bright_cyan]│[/bold bright_cyan]
[bold cyan]    │[/bold cyan]     [bold white]█████[/bold white]  [bold white]██[/bold white]   [bold white]██[/bold white] [bold white]████████[/bold white] [bold white]██[/bold white]  [bold white]██[/bold white] [bold white]███████[/bold white] [bold white]███[/bold white]   [bold white]██[/bold white] [bold white]████████[/bold white] [bold white]█████[/bold white]    [bold cyan]│[/bold cyan]
[bold blue]    │[/bold blue]    [bold white]██   ██[/bold white] [bold white]██[/bold white]   [bold white]██[/bold white]    [bold white]██[/bold white]    [bold white]██[/bold white]  [bold white]██[/bold white] [bold white]██[/bold white]      [bold white]████[/bold white]  [bold white]██[/bold white]    [bold white]██[/bold white]   [bold white]██   ██[/bold white]   [bold blue]│[/bold blue]
[bold bright_blue]    │[/bold bright_blue]    [bold white]███████[/bold white] [bold white]██[/bold white]   [bold white]██[/bold white]    [bold white]██[/bold white]    [bold white]██████[/bold white] [bold white]█████[/bold white]   [bold white]██[/bold white] [bold white]██[/bold white] [bold white]██[/bold white]    [bold white]██[/bold white]    [bold white]█████[/bold white]    [bold bright_blue]│[/bold bright_blue]
[bold blue]    │[/bold blue]    [bold white]██   ██[/bold white] [bold white]██[/bold white]   [bold white]██[/bold white]    [bold white]██[/bold white]    [bold white]██[/bold white]  [bold white]██[/bold white] [bold white]██[/bold white]      [bold white]██[/bold white]  [bold white]████[/bold white]    [bold white]██[/bold white]   [bold white]██   ██[/bold white]   [bold blue]│[/bold blue]
[bold cyan]    │[/bold cyan]    [bold white]██   ██[/bold white]  [bold white]█████[/bold white]     [bold white]██[/bold white]    [bold white]██[/bold white]  [bold white]██[/bold white] [bold white]███████[/bold white] [bold white]██[/bold white]   [bold white]███[/bold white]    [bold white]██[/bold white]    [bold white]█████[/bold white]    [bold cyan]│[/bold cyan]
[bold bright_cyan]    │[/bold bright_cyan]                                                              [bold bright_cyan]│[/bold bright_cyan]
[bold bright_cyan]    ╰──────────────────────────────────────────────────────────────╯[/bold bright_cyan]
"""
    return banner

def print_enhanced_banner():
    """Print the enhanced homepage banner"""
    console.print()
    console.print(get_gradient_banner())
    
    # Tagline box
    tagline = Panel(
        Align.center(
            f"[bold cyan]🔒 Privacy-First Security Scanner[/bold cyan]  [dim]v{__version__}[/dim]\n"
            "[dim]Your code stays local • AI-powered vulnerability detection[/dim]"
        ),
        border_style="bright_black",
        padding=(0, 2)
    )
    console.print(tagline)
    console.print()

def print_mini_header():
    """Print minimal header for sub-pages"""
    console.print()
    console.print(f"[bold cyan]🔒 authent8[/bold cyan] [dim]v{__version__}[/dim]")
    console.print()

def get_tool_status():
    """Get status of installed tools"""
    tools = {
        'trivy': is_installed('trivy'),
        'semgrep': is_installed('semgrep'),
        'gitleaks': is_installed('gitleaks')
    }
    return tools

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN MENU - ENHANCED
# ═══════════════════════════════════════════════════════════════════════════════

def show_main_menu():
    """Display enhanced main menu"""
    clear_screen()
    print_enhanced_banner()
    
    # Tool status indicators
    tools = get_tool_status()
    tool_icons = []
    for name, installed in tools.items():
        if installed:
            tool_icons.append(f"[green]●[/green] {name}")
        else:
            tool_icons.append(f"[red]○[/red] {name}")
    
    console.print(f"    [dim]Scanners:[/dim] {' │ '.join(tool_icons)}")
    console.print()
    
    # Recent scans history
    recent = get_recent_scans(3)
    if recent:
        console.print("[dim]📜 Recent Scans:[/dim]")
        for scan in recent:
            try:
                ts = datetime.fromisoformat(scan['timestamp'])
                time_str = ts.strftime("%m/%d %H:%M")
                path_short = scan['path'].split('/')[-1][:20]
                findings = scan.get('findings', 0)
                crit = scan.get('critical', 0)
                high = scan.get('high', 0)
                
                if crit > 0:
                    status = f"[red]🔴 {crit}C/{high}H[/red]"
                elif high > 0:
                    status = f"[yellow]🟠 {high}H[/yellow]"
                elif findings > 0:
                    status = f"[blue]{findings} issues[/blue]"
                else:
                    status = "[green]✓ Clean[/green]"
                
                console.print(f"    [dim]{time_str}[/dim] {path_short}/ {status}")
            except:
                pass
        console.print()
    
    # Menu options - cleaner grid layout
    menu_table = Table(
        show_header=False,
        box=None,
        padding=(0, 3),
        expand=True
    )
    menu_table.add_column(justify="left", width=40)
    menu_table.add_column(justify="left", width=40)
    
    menu_table.add_row(
        "[bold yellow]1[/bold yellow]  [green]⚡ Quick Scan[/green]\n   [dim]Scan current directory[/dim]",
        "[bold yellow]2[/bold yellow]  [cyan]📂 Browse & Select[/cyan]\n   [dim]Choose a directory to scan[/dim]"
    )
    menu_table.add_row("", "")
    menu_table.add_row(
        "[bold yellow]3[/bold yellow]  [blue]📝 Enter Path[/blue]\n   [dim]Type a specific path[/dim]",
        "[bold yellow]4[/bold yellow]  [magenta]📖 Help[/magenta]\n   [dim]Commands & examples[/dim]"
    )
    menu_table.add_row("", "")
    menu_table.add_row(
        "[bold yellow]5[/bold yellow]  [white]⚙️  Settings[/white]\n   [dim]View configuration[/dim]",
        "[bold yellow]q[/bold yellow]  [red]Exit[/red]\n   [dim]Quit authent8[/dim]"
    )
    
    console.print(Panel(menu_table, border_style="cyan", padding=(1, 2)))
    
    # Pro tips - compact
    console.print()
    console.print("[dim]💡 Tips: [cyan]--no-ai[/cyan] for fast scans • [cyan]-v[/cyan] verbose • [cyan]-o file.json[/cyan] save report[/dim]")
    console.print()
    
    return Prompt.ask("[bold cyan]Select[/bold cyan]", choices=["1", "2", "3", "4", "5", "q"], default="1")

# ═══════════════════════════════════════════════════════════════════════════════
# SCAN OPTIONS - STREAMLINED
# ═══════════════════════════════════════════════════════════════════════════════

def get_scan_options() -> dict:
    """Interactive prompt for scan options"""
    console.print()
    console.print(Panel(
        "[bold]Scan Options[/bold]",
        border_style="cyan",
        padding=(0, 1)
    ))
    
    # AI validation
    use_ai = Confirm.ask("  [cyan]Enable AI validation?[/cyan]", default=True)
    
    # Verbose output
    verbose = Confirm.ask("  [cyan]Show all findings?[/cyan]", default=False)
    
    # Save to file
    save_report = Confirm.ask("  [cyan]Save report to file?[/cyan]", default=False)
    output = None
    if save_report:
        output = Prompt.ask("  [cyan]Filename[/cyan]", default="authent8_report.json")
    
    console.print()
    return {
        'no_ai': not use_ai,
        'verbose': verbose,
        'output': output
    }

# ═══════════════════════════════════════════════════════════════════════════════
# HELP PAGE - ENHANCED
# ═══════════════════════════════════════════════════════════════════════════════

def show_help():
    """Display comprehensive help guide"""
    clear_screen()
    print_mini_header()
    
    help_content = """
[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]
[bold white]                              AUTHENT8 HELP[/bold white]
[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]

[bold yellow]QUICK START[/bold yellow]
  [green]$ authent8[/green]                        Interactive mode
  [green]$ authent8 scan ./project[/green]        Direct scan

[bold yellow]COMMANDS[/bold yellow]
  [cyan]scan <path>[/cyan]      Scan directory for vulnerabilities
  [cyan]browse[/cyan]           Interactive directory browser
  [cyan]config[/cyan]           View settings

[bold yellow]OPTIONS[/bold yellow]
  [cyan]--no-ai[/cyan]          Skip AI (faster: ~5s vs ~30s)
  [cyan]-v, --verbose[/cyan]    Show all findings
  [cyan]-o, --output[/cyan]     Save JSON report

[bold yellow]EXAMPLES[/bold yellow]
  [green]$ authent8 scan ./app --no-ai[/green]           Fast scan
  [green]$ authent8 scan ./src -v -o report.json[/green]  Full report

[bold yellow]SCANNERS[/bold yellow]
  [cyan]Trivy[/cyan]       Dependencies & CVEs
  [cyan]Semgrep[/cyan]     Code security patterns  
  [cyan]Gitleaks[/cyan]    Secrets & API keys

[bold yellow]PRIVACY[/bold yellow]
  • Code NEVER leaves your machine
  • Only finding metadata sent to AI
  • Use --no-ai for fully offline scans
"""
    console.print(help_content)
    console.print("[dim]Press Enter to return...[/dim]")
    input()

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION PAGE
# ═══════════════════════════════════════════════════════════════════════════════

def show_config():
    """Display current configuration"""
    clear_screen()
    print_mini_header()
    
    console.print("[bold]⚙️  Configuration[/bold]")
    console.print()
    
    ai_model = os.getenv("AI_MODEL", "gpt-4o")
    ai_base = os.getenv("OPENAI_BASE_URL", "OpenAI default")
    ai_key = "✓ Set" if os.getenv("OPENAI_API_KEY") else "✗ Not set"
    gh_token = "✓ Set" if os.getenv("GITHUB_TOKEN") else "✗ Not set"
    
    # Settings table
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Setting", style="cyan", width=20)
    table.add_column("Value", width=30)
    table.add_column("Status", width=10)
    
    table.add_row("AI Model", ai_model, "[green]●[/green]" if ai_key == "✓ Set" else "[yellow]○[/yellow]")
    table.add_row("OpenAI Key", ai_key, "[green]✓[/green]" if "✓" in ai_key else "[red]✗[/red]")
    table.add_row("GitHub Token", gh_token, "[green]✓[/green]" if "✓" in gh_token else "[dim]-[/dim]")
    
    console.print(table)
    console.print()
    
    # Tools status
    console.print("[bold]Installed Tools:[/bold]")
    tools = get_tool_status()
    for name, installed in tools.items():
        status = "[green]● Installed[/green]" if installed else "[red]○ Missing[/red]"
        console.print(f"  {name}: {status}")
    
    console.print()
    console.print("[dim]Configure via environment variables or .env file[/dim]")

# ═══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE PATH SELECTOR
# ═══════════════════════════════════════════════════════════════════════════════

def get_dir_info(path: Path) -> dict:
    """Get directory stats"""
    try:
        # Exclude common non-scannable dirs for performance
        exclude = {'node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'venv'}
        
        files = []
        dirs = 0
        extensions = {}
        
        for item in path.iterdir():
            if item.name in exclude:
                continue
            if item.is_dir():
                dirs += 1
            elif item.is_file():
                files.append(item)
                ext = item.suffix.lower() or 'no ext'
                extensions[ext] = extensions.get(ext, 0) + 1
        
        top_ext = sorted(extensions.items(), key=lambda x: -x[1])[:3]
        
        return {
            'files': len(files),
            'dirs': dirs,
            'extensions': top_ext,
            'scannable': any(ext in ['.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.cs'] 
                           for ext in extensions.keys())
        }
    except:
        return {'files': 0, 'dirs': 0, 'extensions': [], 'scannable': False}

def interactive_path_selector() -> Path:
    """Interactive directory browser for selecting scan target"""
    current_path = Path.cwd()
    history = []
    
    while True:
        clear_screen()
        print_mini_header()
        
        console.print("[bold]📂 SELECT DIRECTORY[/bold]")
        console.print()
        console.print(f"[cyan]📍[/cyan] {current_path}")
        
        info = get_dir_info(current_path)
        if info['extensions']:
            ext_str = ", ".join([f"{e[0]}" for e in info['extensions']])
            console.print(f"[dim]   {info['files']} files • {info['dirs']} dirs • {ext_str}[/dim]")
        
        console.print()
        console.print("[dim]─" * 50 + "[/dim]")
        
        try:
            entries = sorted(current_path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
            subdirs = [e for e in entries if e.is_dir() and not e.name.startswith('.')]
        except PermissionError:
            subdirs = []
            console.print("[red]⚠ Permission denied[/red]")
        
        options = {}
        
        if current_path != current_path.parent:
            console.print(f"  [yellow]0[/yellow] [dim]📁 ..[/dim]")
            options['0'] = current_path.parent
        
        for i, subdir in enumerate(subdirs[:8], 1):
            sub_info = get_dir_info(subdir)
            mark = "[green]●[/green]" if sub_info['scannable'] else "[dim]○[/dim]"
            console.print(f"  [yellow]{i}[/yellow] 📁 {subdir.name}/ {mark}")
            options[str(i)] = subdir
        
        if len(subdirs) > 8:
            console.print(f"  [dim]+{len(subdirs) - 8} more[/dim]")
        
        console.print()
        console.print("[dim]─" * 50 + "[/dim]")
        console.print(f"  [green]s[/green] Scan here  [cyan]p[/cyan] Enter path  [cyan]h[/cyan] Home  [red]q[/red] Back")
        console.print()
        
        choice = Prompt.ask("[bold cyan]>[/bold cyan]", default="s").strip().lower()
        
        if choice == 'q':
            return None
        elif choice == 's':
            return current_path
        elif choice == 'p':
            manual = Prompt.ask("[cyan]Path[/cyan]")
            p = Path(manual).expanduser().resolve()
            if p.exists() and p.is_dir():
                history.append(current_path)
                current_path = p
            else:
                console.print("[red]Invalid path![/red]")
                time.sleep(1)
        elif choice == 'h':
            history.append(current_path)
            current_path = Path.home()
        elif choice in options:
            history.append(current_path)
            current_path = options[choice].resolve()

# ═══════════════════════════════════════════════════════════════════════════════
# SCANNING & RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

def run_scan_with_progress(path: str, no_ai: bool = False, output: str = None, verbose: bool = False):
    """Run scan with detailed progress tracking"""
    
    clear_screen()
    print_mini_header()
    
    project_path = Path(path)
    
    # Exclude patterns for file count
    exclude_dirs = {'node_modules', '.git', 'dist', 'build', 'vendor', '__pycache__', 
                    '.venv', 'venv', '.tox', 'coverage', '.nyc_output', '.next', 'out'}
    
    all_files = []
    for f in project_path.rglob('*'):
        if any(excl in f.parts for excl in exclude_dirs):
            continue
        if f.is_file() and f.suffix in ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php', 
                                         '.cs', '.c', '.cpp', '.h', '.rs', '.swift', '.kt', '.scala', '.yaml', 
                                         '.yml', '.json', '.xml', '.sh', '.bash', '.sql', '.html', '.css']:
            all_files.append(f)
    
    total_files = len(all_files)
    
    # Scan header
    console.print(Panel(
        f"[bold]Target:[/bold] {path}\n"
        f"[dim]Files: {total_files} │ AI: {'ON' if not no_ai else 'OFF'}[/dim]",
        title="[bold cyan]🔍 Scanning[/bold cyan]",
        border_style="cyan"
    ))
    console.print()
    
    try:
        orchestrator = ScanOrchestrator(path)
    except ValueError as e:
        console.print(f"[red]✗ Error:[/red] {e}")
        return
    
    start_time = time.time()
    scanner_stats = {}
    all_findings = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}[/bold]"),
        BarColumn(bar_width=25, complete_style="cyan"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False
    ) as progress:
        
        # TRIVY
        trivy_task = progress.add_task("[cyan]Trivy[/cyan]", total=100)
        trivy_findings = orchestrator.run_trivy()
        scanner_stats['trivy'] = len(trivy_findings)
        progress.update(trivy_task, completed=100, description=f"[green]Trivy ✓[/green] {len(trivy_findings)}")
        
        # SEMGREP  
        semgrep_task = progress.add_task("[blue]Semgrep[/blue]", total=100)
        semgrep_findings = orchestrator.run_semgrep()
        scanner_stats['semgrep'] = len(semgrep_findings)
        progress.update(semgrep_task, completed=100, description=f"[green]Semgrep ✓[/green] {len(semgrep_findings)}")
        
        # GITLEAKS
        gitleaks_task = progress.add_task("[magenta]Gitleaks[/magenta]", total=100)
        gitleaks_findings = orchestrator.run_gitleaks()
        scanner_stats['gitleaks'] = len(gitleaks_findings)
        progress.update(gitleaks_task, completed=100, description=f"[green]Gitleaks ✓[/green] {len(gitleaks_findings)}")
        
        all_findings = trivy_findings + semgrep_findings + gitleaks_findings
        
        # AI VALIDATION
        if not no_ai and all_findings:
            api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GITHUB_TOKEN")
            if api_key:
                ai_task = progress.add_task("[yellow]AI Validation[/yellow]", total=len(all_findings))
                
                try:
                    validator = AIValidator(api_key)
                    batch_size = 3
                    validated_findings = []
                    
                    for i in range(0, len(all_findings), batch_size):
                        batch = all_findings[i:i+batch_size]
                        progress.update(ai_task, completed=i, description=f"[yellow]AI[/yellow] {i}/{len(all_findings)}")
                        validated_batch = validator._validate_batch(batch)
                        validated_findings.extend(validated_batch)
                    
                    all_findings = validated_findings
                    false_positives = sum(1 for f in all_findings if f.get("is_false_positive"))
                    progress.update(ai_task, completed=len(all_findings),
                                   description=f"[green]AI ✓[/green] -{false_positives} FP")
                except Exception as e:
                    progress.update(ai_task, completed=len(all_findings),
                                   description=f"[yellow]AI ⚠[/yellow] {str(e)[:20]}")
    
    real_findings = [f for f in all_findings if not f.get("is_false_positive", False)]
    total_time = time.time() - start_time
    
    # Count severities for history
    crit_count = sum(1 for f in real_findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in real_findings if f.get("severity") == "HIGH")
    
    # Save to history
    add_to_history(path, len(real_findings), crit_count, high_count, total_time)
    
    console.print()
    display_results(real_findings, scanner_stats, total_time, verbose)
    
    if output:
        with open(output, 'w') as f:
            json.dump(all_findings, f, indent=2)
        console.print(f"[dim]📄 Saved to {output}[/dim]")

def display_results(findings: list, scanner_stats: dict, total_time: float, verbose: bool = False):
    """Display scan results"""
    
    by_severity = {
        'CRITICAL': [f for f in findings if f.get("severity") == "CRITICAL"],
        'HIGH': [f for f in findings if f.get("severity") == "HIGH"],
        'MEDIUM': [f for f in findings if f.get("severity") == "MEDIUM"],
        'LOW': [f for f in findings if f.get("severity") == "LOW"],
    }
    
    # No findings = success
    if not findings:
        console.print(Panel(
            "[bold green]✓ NO VULNERABILITIES FOUND[/bold green]\n\n"
            "[dim]Your code looks secure![/dim]",
            title="[bold]Scan Complete[/bold]",
            border_style="green"
        ))
        console.print()
        console.print("[dim]🔒 Your code stayed local[/dim]")
        console.print()
        return
    
    # Summary
    crit = len(by_severity['CRITICAL'])
    high = len(by_severity['HIGH'])
    med = len(by_severity['MEDIUM'])
    low = len(by_severity['LOW'])
    
    severity_parts = []
    if crit: severity_parts.append(f"[bold red]{crit} CRITICAL[/bold red]")
    if high: severity_parts.append(f"[yellow]{high} HIGH[/yellow]")
    if med: severity_parts.append(f"[blue]{med} MEDIUM[/blue]")
    if low: severity_parts.append(f"[dim]{low} LOW[/dim]")
    
    status_color = "red" if crit else ("yellow" if high else "blue")
    
    console.print(Panel(
        f"[bold]Found {len(findings)} issues[/bold]\n"
        f"{' • '.join(severity_parts)}\n\n"
        f"[dim]Time: {total_time:.1f}s[/dim]",
        title="[bold]Results[/bold]",
        border_style=status_color
    ))
    
    # Findings table
    console.print()
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold", padding=(0, 1))
    table.add_column("", width=2)
    table.add_column("Issue", max_width=40, overflow="ellipsis")
    table.add_column("Location", max_width=20, overflow="ellipsis")
    table.add_column("Tool", width=8)
    
    sorted_findings = sorted(
        findings,
        key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("severity", "LOW"), 4)
    )
    
    display_limit = 10 if not verbose else 30
    
    for finding in sorted_findings[:display_limit]:
        severity = finding.get("severity", "?")
        message = finding.get("message", finding.get("description", ""))[:40].replace("\n", " ").strip()
        file_loc = Path(finding.get("file", "unknown")).name
        line = finding.get("line", "")
        location = f"{file_loc}:{line}" if line else file_loc
        tool = finding.get("tool", "")[:8]
        
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}.get(severity, "⚪")
        
        table.add_row(sev_icon, message, f"[dim]{location}[/dim]", f"[dim]{tool}[/dim]")
    
    console.print(table)
    
    remaining = len(findings) - display_limit
    if remaining > 0:
        console.print(f"[dim]+{remaining} more (use -v)[/dim]")
    
    # AI suggestions - show ALL findings with suggestions (grouped by file)
    findings_with_fixes = [f for f in sorted_findings if f.get("fix_suggestion")]
    if findings_with_fixes:
        console.print()
        console.print("[bold cyan]💡 Fix Suggestions (All Issues)[/bold cyan]")
        console.print()
        
        # Group by file for cleaner display
        by_file = {}
        for f in findings_with_fixes:
            file_loc = Path(f.get("file", "unknown")).name
            if file_loc not in by_file:
                by_file[file_loc] = []
            by_file[file_loc].append(f)
        
        # Display limit per file in non-verbose, all in verbose
        max_per_file = 10 if verbose else 3
        
        for file_name, file_findings in by_file.items():
            console.print(f"  [bold]{file_name}[/bold]")
            displayed = 0
            for finding in file_findings[:max_per_file]:
                line = finding.get("line", "?")
                fix = finding.get("fix_suggestion", "")
                # Truncate if needed but show full suggestion
                if len(fix) > 80 and not verbose:
                    fix = fix[:77] + "..."
                console.print(f"    [dim]L{line}:[/dim] {fix}")
                displayed += 1
            
            remaining = len(file_findings) - displayed
            if remaining > 0:
                console.print(f"    [dim]+{remaining} more fixes (use -v)[/dim]")
            console.print()
    
    # Warning panel
    console.print()
    if crit:
        console.print(Panel("[bold red]⚠ CRITICAL[/bold red] - Fix immediately!", border_style="red"))
    elif high:
        console.print(Panel("[yellow]⚠ HIGH RISK[/yellow] - Review before deploy", border_style="yellow"))
    
    console.print()
    console.print("[dim]🔒 Your code stayed local[/dim]")
    console.print()

# ═══════════════════════════════════════════════════════════════════════════════
# CLI COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="authent8")
@click.pass_context
def cli(ctx):
    """Authent8 - Privacy-First Security Scanner
    
    Scan your code for vulnerabilities using Trivy, Semgrep, and Gitleaks.
    AI-powered validation helps reduce false positives.
    """
    check_first_run()
    
    if ctx.invoked_subcommand is None:
        ctx.invoke(run)

@cli.command()
def run():
    """Interactive mode - main menu"""
    while True:
        choice = show_main_menu()
        
        if choice == "q":
            console.print("\n[cyan]Goodbye! 🔒[/cyan]\n")
            sys.exit(0)
        
        elif choice == "1":
            options = get_scan_options()
            run_scan_with_progress(str(Path.cwd()), **options)
            input("\n[dim]Press Enter...[/dim]")
        
        elif choice == "2":
            target = interactive_path_selector()
            if target:
                options = get_scan_options()
                run_scan_with_progress(str(target), **options)
                input("\n[dim]Press Enter...[/dim]")
        
        elif choice == "3":
            console.print()
            path_str = Prompt.ask("[cyan]Path[/cyan]")
            target = Path(path_str).expanduser().resolve()
            if not target.exists():
                console.print("[red]Path not found![/red]")
                time.sleep(1)
                continue
            options = get_scan_options()
            run_scan_with_progress(str(target), **options)
            input("\n[dim]Press Enter...[/dim]")
        
        elif choice == "4":
            show_help()
        
        elif choice == "5":
            show_config()
            input("\n[dim]Press Enter...[/dim]")

@cli.command()
@click.argument('path', type=click.Path(exists=True), required=False)
@click.option('--no-ai', is_flag=True, help='Skip AI validation')
@click.option('--output', '-o', type=click.Path(), help='Save JSON report')
@click.option('--verbose', '-v', is_flag=True, help='Show all findings')
def scan(path, no_ai, output, verbose):
    """Scan a directory for vulnerabilities"""
    if path is None:
        path = str(interactive_path_selector() or Path.cwd())
    run_scan_with_progress(path, no_ai, output, verbose)

@cli.command()
def browse():
    """Interactive directory browser"""
    target = interactive_path_selector()
    if target:
        use_ai = Confirm.ask("[cyan]Enable AI?[/cyan]", default=True)
        run_scan_with_progress(str(target), no_ai=not use_ai)

@cli.command()
def config():
    """Show configuration"""
    show_config()

if __name__ == "__main__":
    cli()
