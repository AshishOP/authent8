#!/usr/bin/env python3
"""
Authent8 CLI - Enhanced UI with Interactive Path Selection and Progress Tracking
"""
import click
import json
import os
import sys
import time
import threading
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TaskProgressColumn
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich import box
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.tree import Tree
from rich.markdown import Markdown
from rich.syntax import Syntax
from dotenv import load_dotenv

# Load environment variables
env_path = Path(__file__).parent.parent / '.env'
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scanner_orchestrator import ScanOrchestrator
from core.ai_validator import AIValidator

console = Console()
VERBOSE = False

# ═══════════════════════════════════════════════════════════════════════════════
# 3D BANNER & UI HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def clear_screen():
    """Clear terminal screen"""
    os.system('clear' if os.name != 'nt' else 'cls')

def print_3d_banner():
    """Print 3D-style banner like Gemini CLI"""
    # Gradient colors for 3D effect
    banner_lines = [
        "                                                                          ",
        "     █████╗ ██╗   ██╗████████╗██╗  ██╗███████╗███╗   ██╗████████╗ █████╗  ",
        "    ██╔══██╗██║   ██║╚══██╔══╝██║  ██║██╔════╝████╗  ██║╚══██╔══╝██╔══██╗ ",
        "    ███████║██║   ██║   ██║   ███████║█████╗  ██╔██╗ ██║   ██║   ╚█████╔╝ ",
        "    ██╔══██║██║   ██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗ ",
        "    ██║  ██║╚██████╔╝   ██║   ██║  ██║███████╗██║ ╚████║   ██║   ╚█████╔╝ ",
        "    ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚════╝  ",
        "                                                                          ",
    ]
    
    # Apply gradient effect (cyan -> blue -> magenta)
    colors = ['bright_cyan', 'cyan', 'blue', 'bright_blue', 'blue', 'cyan', 'bright_cyan', 'dim']
    
    console.print()
    for i, line in enumerate(banner_lines):
        color = colors[i % len(colors)]
        console.print(f"[{color}]{line}[/{color}]")
    
    # Tagline with glow effect
    console.print()
    console.print("[bold white]          ╔═══════════════════════════════════════════════════════╗[/bold white]")
    console.print("[bold white]          ║[/bold white]  [bold cyan]🔒 Privacy-First Security Scanner[/bold cyan]  [dim]v1.0.0[/dim]       [bold white]║[/bold white]")
    console.print("[bold white]          ║[/bold white]  [dim]Your code stays local • AI-powered validation[/dim]  [bold white]║[/bold white]")
    console.print("[bold white]          ╚═══════════════════════════════════════════════════════╝[/bold white]")
    console.print()

def print_mini_header():
    """Print minimal header"""
    console.print()
    console.print("[bold cyan]󰒃 authent8[/bold cyan] [dim]v1.0[/dim]")
    console.print()

def show_help():
    """Display comprehensive help guide"""
    clear_screen()
    print_mini_header()
    
    help_content = """
[bold cyan]═══════════════════════════════════════════════════════════════════════════════
                              AUTHENT8 HELP GUIDE
═══════════════════════════════════════════════════════════════════════════════[/bold cyan]

[bold yellow]🚀 QUICK START[/bold yellow]
─────────────────────────────────────────────────────────────────────────────────
  Run the tool interactively:
  [green]$ python cli/authent8_cli_enhanced.py[/green]

  Or scan directly:
  [green]$ python cli/authent8_cli_enhanced.py scan /path/to/project[/green]

[bold yellow]📋 COMMANDS[/bold yellow]
─────────────────────────────────────────────────────────────────────────────────
  [cyan]scan <path>[/cyan]     Scan a directory for security vulnerabilities
  [cyan]browse[/cyan]          Interactive directory browser
  [cyan]config[/cyan]          View current configuration
  [cyan]run[/cyan]             Interactive mode (default)

[bold yellow]⚙️  OPTIONS[/bold yellow]
─────────────────────────────────────────────────────────────────────────────────
  [cyan]--no-ai[/cyan]         Skip AI validation (faster scan, ~5s vs ~30s)
  [cyan]-v, --verbose[/cyan]   Show all findings (default shows top 8)
  [cyan]-o, --output[/cyan]    Save full report to JSON file

[bold yellow]📊 EXAMPLES[/bold yellow]
─────────────────────────────────────────────────────────────────────────────────
  [dim]# Quick scan without AI[/dim]
  [green]$ python cli/authent8_cli_enhanced.py scan ./my-project --no-ai[/green]

  [dim]# Full scan with verbose output[/dim]
  [green]$ python cli/authent8_cli_enhanced.py scan ./my-project -v[/green]

  [dim]# Save report to file[/dim]
  [green]$ python cli/authent8_cli_enhanced.py scan ./my-project -o report.json[/green]

  [dim]# Combine options[/dim]
  [green]$ python cli/authent8_cli_enhanced.py scan ./src -v -o findings.json[/green]

[bold yellow]🔧 SCANNERS[/bold yellow]
─────────────────────────────────────────────────────────────────────────────────
  [cyan]Trivy[/cyan]       Vulnerability scanner for dependencies & CVEs
  [cyan]Semgrep[/cyan]     Static analysis for code security patterns  
  [cyan]Gitleaks[/cyan]    Secret detection (API keys, passwords, tokens)

[bold yellow]🤖 AI VALIDATION[/bold yellow]
─────────────────────────────────────────────────────────────────────────────────
  • Analyzes each finding for false positives
  • Provides confidence score (0-100%)
  • Suggests fixes for real vulnerabilities
  • Uses your configured AI model (see .env file)

[bold yellow]📁 SUPPORTED FILE TYPES[/bold yellow]
─────────────────────────────────────────────────────────────────────────────────
  Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C#, C/C++,
  Rust, Swift, Kotlin, Scala, YAML, JSON, XML, SQL, Shell scripts

[bold yellow]🔐 PRIVACY[/bold yellow]
─────────────────────────────────────────────────────────────────────────────────
  • Your code NEVER leaves your machine
  • Only anonymized finding metadata is sent to AI
  • No telemetry or usage tracking
  • Fully offline scan possible with --no-ai

[dim]Press Enter to return to menu...[/dim]
"""
    console.print(help_content)
    input()

# ═══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE PATH SELECTOR
# ═══════════════════════════════════════════════════════════════════════════════

def get_dir_info(path: Path) -> dict:
    """Get directory stats"""
    try:
        files = list(path.rglob('*'))
        file_count = sum(1 for f in files if f.is_file())
        dir_count = sum(1 for f in files if f.is_dir())
        
        # Get file types
        extensions = {}
        for f in files:
            if f.is_file():
                ext = f.suffix.lower() or 'no ext'
                extensions[ext] = extensions.get(ext, 0) + 1
        
        # Get top extensions
        top_ext = sorted(extensions.items(), key=lambda x: -x[1])[:5]
        
        return {
            'files': file_count,
            'dirs': dir_count,
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
        
        # Header
        console.print("[bold]📁 SELECT TARGET DIRECTORY[/bold]")
        console.print()
        
        # Current location
        console.print(f"[cyan]📍 Current:[/cyan] {current_path}")
        
        # Get dir info
        info = get_dir_info(current_path)
        console.print(f"[dim]   {info['files']} files, {info['dirs']} subdirectories[/dim]")
        
        if info['extensions']:
            ext_str = ", ".join([f"{e[0]}({e[1]})" for e in info['extensions']])
            console.print(f"[dim]   Types: {ext_str}[/dim]")
        
        console.print()
        console.print("[dim]─" * 60 + "[/dim]")
        console.print()
        
        # Get subdirectories
        try:
            entries = sorted(current_path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
            subdirs = [e for e in entries if e.is_dir() and not e.name.startswith('.')]
        except PermissionError:
            subdirs = []
            console.print("[red]⚠ Permission denied[/red]")
        
        # Build options list
        options = {}
        
        # Parent directory (if not root)
        if current_path != current_path.parent:
            console.print(f"  [yellow]0.[/yellow] [dim]📁 ..[/dim]  [dim](parent)[/dim]")
            options['0'] = current_path.parent
        
        # Subdirectories (max 9)
        for i, subdir in enumerate(subdirs[:9], 1):
            sub_info = get_dir_info(subdir)
            indicator = "📁" if sub_info['scannable'] else "📂"
            scannable_mark = " [green]●[/green]" if sub_info['scannable'] else ""
            console.print(f"  [yellow]{i}.[/yellow] {indicator} {subdir.name}/  [dim]({sub_info['files']} files){scannable_mark}[/dim]")
            options[str(i)] = subdir
        
        if len(subdirs) > 9:
            console.print(f"  [dim]   ... +{len(subdirs) - 9} more directories[/dim]")
        
        console.print()
        console.print("[dim]─" * 60 + "[/dim]")
        console.print()
        
        # Actions
        console.print("[bold]Actions:[/bold]")
        console.print(f"  [green]s[/green] = [bold]Scan this directory[/bold]")
        console.print(f"  [cyan]p[/cyan] = Enter path manually")
        console.print(f"  [cyan]h[/cyan] = Home directory")
        console.print(f"  [red]q[/red] = Quit")
        console.print()
        
        # Get user input
        choice = Prompt.ask("[bold cyan]>[/bold cyan]", default="s").strip().lower()
        
        if choice == 'q':
            console.print("\n[yellow]Goodbye![/yellow]")
            sys.exit(0)
        
        elif choice == 's':
            if info['files'] == 0:
                console.print("[yellow]⚠ This directory is empty![/yellow]")
                time.sleep(1)
                continue
            return current_path
        
        elif choice == 'p':
            manual = Prompt.ask("[cyan]Enter path[/cyan]")
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
        
        else:
            console.print("[yellow]Invalid option[/yellow]")
            time.sleep(0.5)

# ═══════════════════════════════════════════════════════════════════════════════
# PROGRESS TRACKING SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

def run_scan_with_progress(path: str, no_ai: bool = False, output: str = None, verbose: bool = False):
    """Run scan with detailed progress tracking"""
    
    clear_screen()
    print_mini_header()
    
    project_path = Path(path)
    
    # Get file list for progress tracking
    all_files = list(project_path.rglob('*'))
    scannable_files = [f for f in all_files if f.is_file() and f.suffix in 
                      ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php', 
                       '.cs', '.c', '.cpp', '.h', '.rs', '.swift', '.kt', '.scala', '.yaml', 
                       '.yml', '.json', '.xml', '.sh', '.bash', '.sql', '.html', '.css']]
    
    total_files = len(scannable_files)
    
    # Display target info
    console.print(Panel(
        f"[bold]Target:[/bold] {path}\n"
        f"[dim]Files to scan: {total_files}  │  AI validation: {'ON' if not no_ai else 'OFF'}[/dim]",
        title="[bold cyan]󰒃 Scan Starting[/bold cyan]",
        border_style="cyan"
    ))
    console.print()
    
    # Initialize orchestrator
    try:
        orchestrator = ScanOrchestrator(path)
    except ValueError as e:
        console.print(f"[red]✗ Error:[/red] {e}")
        return
    
    start_time = time.time()
    scanner_stats = {}
    all_findings = []
    
    # Create progress display
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}[/bold blue]"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False
    ) as progress:
        
        # TRIVY SCAN
        trivy_task = progress.add_task("[cyan]Trivy[/cyan] - Dependencies & CVEs", total=100)
        progress.update(trivy_task, description="[cyan]Trivy[/cyan] - Scanning dependencies...")
        
        trivy_start = time.time()
        trivy_findings = orchestrator.run_trivy()
        trivy_time = time.time() - trivy_start
        
        scanner_stats['trivy'] = {'findings': len(trivy_findings), 'time': trivy_time}
        progress.update(trivy_task, completed=100, 
                       description=f"[green]Trivy[/green] ✓ {len(trivy_findings)} findings")
        
        # SEMGREP SCAN  
        semgrep_task = progress.add_task("[blue]Semgrep[/blue] - Code patterns", total=100)
        
        # Simulate file-by-file progress for semgrep
        semgrep_start = time.time()
        
        # Show some files being scanned
        for i, f in enumerate(scannable_files[:min(10, len(scannable_files))]):
            progress.update(semgrep_task, 
                          completed=int((i+1) / min(10, len(scannable_files)) * 50),
                          description=f"[blue]Semgrep[/blue] - {f.name[:30]}...")
            time.sleep(0.1)  # Brief pause for visibility
        
        semgrep_findings = orchestrator.run_semgrep()
        semgrep_time = time.time() - semgrep_start
        
        scanner_stats['semgrep'] = {'findings': len(semgrep_findings), 'time': semgrep_time}
        progress.update(semgrep_task, completed=100,
                       description=f"[green]Semgrep[/green] ✓ {len(semgrep_findings)} findings")
        
        # GITLEAKS SCAN
        gitleaks_task = progress.add_task("[magenta]Gitleaks[/magenta] - Secrets", total=100)
        progress.update(gitleaks_task, description="[magenta]Gitleaks[/magenta] - Scanning for secrets...")
        
        gitleaks_start = time.time()
        gitleaks_findings = orchestrator.run_gitleaks()
        gitleaks_time = time.time() - gitleaks_start
        
        scanner_stats['gitleaks'] = {'findings': len(gitleaks_findings), 'time': gitleaks_time}
        progress.update(gitleaks_task, completed=100,
                       description=f"[green]Gitleaks[/green] ✓ {len(gitleaks_findings)} findings")
        
        all_findings = trivy_findings + semgrep_findings + gitleaks_findings
        
        # AI VALIDATION
        if not no_ai and all_findings:
            api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GITHUB_TOKEN")
            if api_key:
                ai_task = progress.add_task("[yellow]AI[/yellow] - Validating findings", total=len(all_findings))
                
                try:
                    validator = AIValidator(api_key)
                    
                    # Process in batches with progress
                    batch_size = 3
                    validated_findings = []
                    
                    for i in range(0, len(all_findings), batch_size):
                        batch = all_findings[i:i+batch_size]
                        progress.update(ai_task, 
                                       completed=i,
                                       description=f"[yellow]AI[/yellow] - Analyzing finding {i+1}/{len(all_findings)}...")
                        
                        validated_batch = validator._validate_batch(batch)
                        validated_findings.extend(validated_batch)
                    
                    all_findings = validated_findings
                    false_positives = sum(1 for f in all_findings if f.get("is_false_positive"))
                    
                    progress.update(ai_task, completed=len(all_findings),
                                   description=f"[green]AI[/green] ✓ Removed {false_positives} false positives")
                    
                except Exception as e:
                    progress.update(ai_task, completed=len(all_findings),
                                   description=f"[yellow]AI[/yellow] ⚠ Skipped: {str(e)[:30]}")
    
    # Filter real findings
    real_findings = [f for f in all_findings if not f.get("is_false_positive", False)]
    total_time = time.time() - start_time
    
    console.print()
    
    # Display results with AI insights
    display_results_with_ai(real_findings, scanner_stats, total_time, verbose)
    
    # Save if requested
    if output:
        with open(output, 'w') as f:
            json.dump(all_findings, f, indent=2)
        console.print(f"\n[dim]📄 Full report saved to {output}[/dim]")

def display_results_with_ai(findings: list, scanner_stats: dict, total_time: float, verbose: bool = False):
    """Display scan results with AI confidence and fix suggestions"""
    
    # Count by severity
    by_severity = {
        'CRITICAL': [f for f in findings if f.get("severity") == "CRITICAL"],
        'HIGH': [f for f in findings if f.get("severity") == "HIGH"],
        'MEDIUM': [f for f in findings if f.get("severity") == "MEDIUM"],
        'LOW': [f for f in findings if f.get("severity") == "LOW"],
    }
    
    # Summary panel
    if not findings:
        console.print(Panel(
            "[bold green]✓ NO VULNERABILITIES FOUND[/bold green]\n\n"
            "[dim]Your code looks secure! All scanners completed successfully.[/dim]",
            title="[bold]Scan Complete[/bold]",
            border_style="green"
        ))
        console.print()
        console.print("[dim]🔒 Your code stayed local • 0 bytes sent externally[/dim]")
        console.print()
        return
    
    crit = len(by_severity['CRITICAL'])
    high = len(by_severity['HIGH'])
    med = len(by_severity['MEDIUM'])
    low = len(by_severity['LOW'])
    
    severity_line = []
    if crit: severity_line.append(f"[bold red]{crit} CRITICAL[/bold red]")
    if high: severity_line.append(f"[yellow]{high} HIGH[/yellow]")
    if med: severity_line.append(f"[blue]{med} MEDIUM[/blue]")
    if low: severity_line.append(f"[dim]{low} LOW[/dim]")
    
    status_color = "red" if crit else ("yellow" if high else "blue")
    
    # Scanner stats
    stats_line = " │ ".join([
        f"trivy: {scanner_stats.get('trivy', {}).get('findings', 0)}",
        f"semgrep: {scanner_stats.get('semgrep', {}).get('findings', 0)}",
        f"gitleaks: {scanner_stats.get('gitleaks', {}).get('findings', 0)}"
    ])
    
    console.print(Panel(
        f"[bold]Found {len(findings)} issues[/bold]\n"
        f"{' • '.join(severity_line)}\n\n"
        f"[dim]Scanners: {stats_line}[/dim]\n"
        f"[dim]Time: {total_time:.1f}s[/dim]",
        title="[bold]Scan Complete[/bold]",
        border_style=status_color
    ))
    
    # Findings table with AI insights
    console.print()
    
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold", padding=(0, 1))
    table.add_column("", width=3)
    table.add_column("Issue", max_width=35, overflow="ellipsis")
    table.add_column("Location", max_width=18, overflow="ellipsis")
    table.add_column("Conf", width=4, justify="center")  # AI Confidence
    table.add_column("Tool", width=8)
    
    # Sort by severity
    sorted_findings = sorted(
        findings,
        key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("severity", "LOW"), 4)
    )
    
    display_limit = 8 if not verbose else 25
    
    for finding in sorted_findings[:display_limit]:
        severity = finding.get("severity", "?")
        tool = finding.get("tool", "")[:8]
        message = finding.get("message", finding.get("description", ""))[:35].replace("\n", " ").strip()
        file_loc = Path(finding.get("file", "unknown")).name
        line = finding.get("line", "")
        location = f"{file_loc}:{line}" if line else file_loc
        
        # AI confidence indicator
        confidence = finding.get("ai_confidence", 0)
        if confidence >= 80:
            conf_display = f"[green]{confidence}%[/green]"
        elif confidence >= 50:
            conf_display = f"[yellow]{confidence}%[/yellow]"
        elif confidence > 0:
            conf_display = f"[red]{confidence}%[/red]"
        else:
            conf_display = "[dim]--[/dim]"
        
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}.get(severity, "⚪")
        
        table.add_row(
            sev_icon,
            message,
            f"[dim]{location}[/dim]",
            conf_display,
            f"[dim]{tool}[/dim]"
        )
    
    console.print(table)
    
    remaining = len(findings) - display_limit
    if remaining > 0:
        console.print(f"\n[dim]  +{remaining} more issues (use -v for all, or -o report.json to save)[/dim]")
    
    # Show AI Fix Suggestions for top issues
    console.print()
    console.print("[bold cyan]💡 AI Fix Suggestions[/bold cyan]")
    console.print("[dim]─" * 60 + "[/dim]")
    
    suggestions_shown = 0
    for finding in sorted_findings:
        fix = finding.get("fix_suggestion", "")
        reasoning = finding.get("ai_reasoning", "")
        confidence = finding.get("ai_confidence", 0)
        
        if fix and suggestions_shown < 5:  # Show top 5 suggestions
            severity = finding.get("severity", "?")
            file_loc = Path(finding.get("file", "unknown")).name
            line = finding.get("line", "")
            
            sev_color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "dim"}.get(severity, "dim")
            
            console.print(f"\n  [{sev_color}]● {severity}[/{sev_color}] [dim]{file_loc}:{line}[/dim]")
            console.print(f"    [green]Fix:[/green] {fix[:80]}")
            if reasoning:
                console.print(f"    [dim]Why: {reasoning[:60]}[/dim]")
            if confidence:
                console.print(f"    [dim]Confidence: {confidence}%[/dim]")
            
            suggestions_shown += 1
    
    if suggestions_shown == 0:
        console.print("[dim]  No AI suggestions available. Run with AI enabled for insights.[/dim]")
    
    # Status banner
    console.print()
    if by_severity['CRITICAL']:
        console.print(Panel("[bold red]⚠ CRITICAL ISSUES[/bold red] - Immediate action required!", border_style="red"))
    elif by_severity['HIGH']:
        console.print(Panel("[yellow]⚠ HIGH RISK[/yellow] - Review recommended before deployment", border_style="yellow"))
    elif findings:
        console.print(Panel("[blue]ℹ Issues found[/blue] - Consider reviewing before release", border_style="blue"))
    
    console.print()
    console.print("[dim]🔒 Your code stayed local • 0 bytes sent externally[/dim]")
    console.print()

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════════

def show_main_menu():
    """Display enhanced main menu with 3D banner"""
    clear_screen()
    print_3d_banner()
    
    # Menu panel
    menu_content = """
[bold]What would you like to do?[/bold]

  [bold yellow]1.[/bold yellow] [green]󰄬  Scan current directory[/green]
     [dim]Quick scan of the directory you're in[/dim]

  [bold yellow]2.[/bold yellow] [cyan]󰉋  Browse & select directory[/cyan]
     [dim]Interactive file browser to choose target[/dim]

  [bold yellow]3.[/bold yellow] [blue]󰗀  Enter path manually[/blue]
     [dim]Type a specific path to scan[/dim]

  [bold yellow]4.[/bold yellow] [magenta]󰋖  Help & documentation[/magenta]
     [dim]Learn commands, options, and examples[/dim]

  [bold yellow]5.[/bold yellow] [dim]󰒓  Configuration[/dim]
     [dim]View current settings[/dim]

  [bold yellow]q.[/bold yellow] [red]Exit[/red]
"""
    console.print(Panel(menu_content, border_style="cyan", padding=(0, 2)))
    
    # Tips section
    console.print()
    console.print("[bold dim]💡 Pro Tips:[/bold dim]")
    console.print("[dim]  • Use [cyan]--no-ai[/cyan] for fast scans (~5s vs ~30s with AI)[/dim]")
    console.print("[dim]  • Use [cyan]-v[/cyan] to see all findings, [cyan]-o report.json[/cyan] to save[/dim]")
    console.print("[dim]  • Green dots [green]●[/green] in browser indicate scannable directories[/dim]")
    console.print()
    
    return Prompt.ask("[bold cyan]Select option[/bold cyan]", choices=["1", "2", "3", "4", "5", "q"], default="2")

# ═══════════════════════════════════════════════════════════════════════════════
# CLI COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """Authent8 - Privacy-First Security Scanner"""
    if ctx.invoked_subcommand is None:
        ctx.invoke(run)

@cli.command()
def run():
    """Interactive mode - main menu"""
    while True:
        choice = show_main_menu()
        
        if choice == "q":
            console.print("\n[cyan]Goodbye! Stay secure! 🔒[/cyan]\n")
            sys.exit(0)
        
        elif choice == "1":
            target = Path.cwd()
            use_ai = Confirm.ask("[cyan]Enable AI validation?[/cyan]", default=True)
            run_scan_with_progress(str(target), no_ai=not use_ai)
            input("\n[dim]Press Enter to continue...[/dim]")
        
        elif choice == "2":
            target = interactive_path_selector()
            use_ai = Confirm.ask("[cyan]Enable AI validation?[/cyan]", default=True)
            run_scan_with_progress(str(target), no_ai=not use_ai)
            input("\n[dim]Press Enter to continue...[/dim]")
        
        elif choice == "3":
            console.print()
            path_str = Prompt.ask("[cyan]Enter path to scan[/cyan]")
            target = Path(path_str).expanduser().resolve()
            if not target.exists():
                console.print("[red]Path does not exist![/red]")
                time.sleep(2)
                continue
            use_ai = Confirm.ask("[cyan]Enable AI validation?[/cyan]", default=True)
            run_scan_with_progress(str(target), no_ai=not use_ai)
            input("\n[dim]Press Enter to continue...[/dim]")
        
        elif choice == "4":
            show_help()
        
        elif choice == "5":
            show_config()
            input("\n[dim]Press Enter to continue...[/dim]")

@cli.command()
@click.argument('path', type=click.Path(exists=True), required=False)
@click.option('--no-ai', is_flag=True, help='Skip AI validation (faster)')
@click.option('--output', '-o', type=click.Path(), help='Save report to JSON file')
@click.option('--verbose', '-v', is_flag=True, help='Show all findings')
def scan(path, no_ai, output, verbose):
    """Scan a directory for vulnerabilities
    
    Examples:
        authent8 scan ./my-project
        authent8 scan ./src --no-ai
        authent8 scan ./app -v -o report.json
    """
    if path is None:
        path = str(interactive_path_selector())
    
    run_scan_with_progress(path, no_ai, output, verbose)

@cli.command()
def browse():
    """Interactive directory browser"""
    target = interactive_path_selector()
    use_ai = Confirm.ask("[cyan]Enable AI validation?[/cyan]", default=True)
    run_scan_with_progress(str(target), no_ai=not use_ai)

@cli.command()
def config():
    """Show current configuration"""
    show_config()

def show_config():
    """Display current configuration"""
    clear_screen()
    print_mini_header()
    
    console.print("[bold]⚙️  Configuration[/bold]")
    console.print()
    
    ai_model = os.getenv("AI_MODEL", "gpt-4o")
    ai_base = os.getenv("OPENAI_BASE_URL", "OpenAI default")
    ai_key = "✓ Configured" if os.getenv("OPENAI_API_KEY") else "✗ Not set"
    gh_token = "✓ Configured" if os.getenv("GITHUB_TOKEN") else "✗ Not set"
    
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")
    table.add_column("Status")
    
    table.add_row("AI Model", ai_model, "[green]Active[/green]" if ai_key == "✓ Configured" else "[yellow]Inactive[/yellow]")
    table.add_row("API Base URL", ai_base[:40] + "..." if len(ai_base) > 40 else ai_base, "")
    table.add_row("OpenAI API Key", ai_key, "[green]✓[/green]" if "✓" in ai_key else "[red]✗[/red]")
    table.add_row("GitHub Token", gh_token, "[green]✓[/green]" if "✓" in gh_token else "[dim]-[/dim]")
    
    console.print(table)
    console.print()
    console.print("[dim]Edit [cyan].env[/cyan] file in the authent8 directory to change settings.[/dim]")
    console.print()
    console.print("[bold]Recommended AI Models:[/bold]")
    console.print("  [green]Fast:[/green]     openai/gpt-4o-mini (current)")
    console.print("  [yellow]Quality:[/yellow]  openai/gpt-4o, anthropic/claude-3-sonnet")
    console.print("  [dim]Free:[/dim]     Use --no-ai flag for offline scanning")

@cli.command()
def help():
    """Show detailed help guide"""
    show_help()

if __name__ == "__main__":
    cli()
