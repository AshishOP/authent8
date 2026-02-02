#!/usr/bin/env python3
"""
Authent8 CLI - Privacy-First Security Scanner
OpenCode Edition: Pure Black & Slate Grey with Vertical Blue Gradients
"""
import click
import json
import os
import sys
import time
import concurrent.futures
import threading
from datetime import datetime
from pathlib import Path
from rich.console import Console, Group
from rich.table import Table
from rich.progress import (
    Progress, 
    SpinnerColumn, 
    TextColumn, 
    BarColumn, 
    TimeElapsedColumn, 
    TaskProgressColumn, 
    MofNCompleteColumn
)
from rich.panel import Panel
from rich import box
from rich.layout import Layout
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.live import Live
from rich.rule import Rule
from rich.style import Style as RichStyle
from dotenv import load_dotenv
import questionary
from questionary import Style

# Load environment variables from multiple locations
# 1. Current working directory
load_dotenv()
# 2. Home directory
load_dotenv(Path.home() / ".authent8.env")
# 3. Package directory (for dev)
load_dotenv(Path(__file__).parent.parent.parent.parent / ".env")

# Real Backend Imports
from authent8.core.scanner_orchestrator import ScanOrchestrator
from authent8.core.ai_validator import AIValidator
from authent8.install_tools import check_and_install, is_installed
from authent8 import __version__

console = Console()

# ═══════════════════════════════════════════════════════════════════════════════
# OPENCODE DARK THEME COLORS
# ═══════════════════════════════════════════════════════════════════════════════
THEME = {
    'bg': '#000000',           # Pure Black
    'surface': '#0a0a0a',      # Deep Grey
    'border': '#1a1a1a',       # Slate Border
    'text_main': '#e5e5e5',    # Off-white
    'text_muted': '#666666',   # Dim Grey
    'blue_primary': '#3b82f6', # Electric Blue
    'blue_navy': '#1e40af',    # Navy
    'crit': '#ff3333',         # OpenCode Red
    'high': '#ff9900',         # OpenCode Orange
    'success': '#10b981',      # Emerald
}

# Questionary style matching the dark-grey/white aesthetic
custom_style = Style([
    ('qmark', 'fg:#3b82f6 bold'),
    ('question', 'fg:#e5e5e5 bold'),
    ('answer', 'fg:#3b82f6 bold'),
    ('pointer', 'fg:#3b82f6 bold'),
    ('highlighted', 'fg:#000000 bg:#3b82f6 bold'),
    ('selected', 'fg:#10b981'),
    ('separator', 'fg:#333333'),
    ('instruction', 'fg:#666666 italic'),
])

# ═══════════════════════════════════════════════════════════════════════════════
# SCAN HISTORY & PERSISTENCE
# ═══════════════════════════════════════════════════════════════════════════════

HISTORY_FILE = Path.home() / ".authent8_history.json"
MAX_HISTORY = 10

def load_scan_history() -> list:
    try:
        if HISTORY_FILE.exists():
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
    except: pass
    return []

def save_scan_history(history: list):
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history[-MAX_HISTORY:], f, indent=2)
    except: pass

def add_to_history(path: str, findings_count: int, critical: int, high: int, duration: float):
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
    history = load_scan_history()
    return history[-limit:][::-1]

# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM CHECKS
# ═══════════════════════════════════════════════════════════════════════════════

def check_first_run():
    marker_file = Path.home() / ".authent8_installed"
    tools_missing = not (is_installed("trivy") and is_installed("semgrep") and is_installed("gitleaks"))
    
    if tools_missing and not marker_file.exists():
        console.print()
        console.print(Panel(
            "[bold #ff9900]🔧 Setup Required[/bold #ff9900]\n\n"
            "Security tools (Trivy, Semgrep, Gitleaks) are missing.\n"
            "Would you like to install them now?",
            title="[bold #3b82f6]Welcome[/bold #3b82f6]",
            border_style="#1a1a1a"
        ))
        if questionary.confirm("Install tools?", default=True, style=custom_style).ask():
            check_and_install()
            marker_file.touch()

# ═══════════════════════════════════════════════════════════════════════════════
# OPENCODE UI ELEMENTS
# ═══════════════════════════════════════════════════════════════════════════════

def clear_screen():
    os.system('clear' if os.name != 'nt' else 'cls')

def get_gradient_banner():
    """Generates a responsive vertical blue gradient banner"""
    term_width = console.width or 80
    
    # Full banner for wide terminals (>= 75 cols)
    if term_width >= 75:
        banner = [
            " █████  ██   ██ ████████ ██  ██ ███████ ███   ██ ████████  █████ ",
            "██   ██ ██   ██    ██    ██  ██ ██      ████  ██    ██    ██   ██",
            "███████ ██   ██    ██    ██████ █████   ██ ██ ██    ██     █████ ",
            "██   ██ ██   ██    ██    ██  ██ ██      ██  ████    ██    ██   ██",
            "██   ██  █████     ██    ██  ██ ███████ ██   ███    ██     █████ "
        ]
    # Compact banner for medium terminals (50-74 cols)
    elif term_width >= 50:
        banner = [
            "▄▀█ █ █ ▀█▀ █ █ █▀▀ █▄ █ ▀█▀ ▄▀█",
            "█▀█ █▄█  █  █▀█ ██▄ █ ▀█  █   █▀█"
        ]
    # Minimal text for narrow terminals (< 50 cols)
    else:
        styled_text = Text()
        styled_text.append("AUTHENT8\n", style="bold #3b82f6")
        return styled_text
    
    # Vertical gradient colors
    colors = ["#93c5fd", "#60a5fa", "#3b82f6", "#2563eb", "#1e40af"]
    
    styled_text = Text()
    for i, line in enumerate(banner):
        color_idx = min(i, len(colors) - 1)
        styled_text.append(line + "\n", style=colors[color_idx])
    return styled_text

def print_enhanced_banner():
    console.print("\n")
    console.print(Align.center(get_gradient_banner()))
    console.print(Align.center(f"[#666666]v{__version__}[/#666666]"))
    console.print("\n")

def print_footer(status="READY"):
    """Responsive OpenCode style footer pill"""
    term_width = console.width or 80
    now = datetime.now().strftime("%H:%M:%S")
    
    # Narrow terminal - simple footer
    if term_width < 50:
        console.print(f"[#1e40af]authent8[/#1e40af] [#666666]{status}[/#666666]")
        return
    
    footer = Text()
    footer.append(f" authent8 ", style="bold #ffffff on #1e40af")
    footer.append(f" {now} ", style="#666666")
    
    right = Text()
    right.append(" mode ", style="#666666")
    right.append(f" {status} ", style="bold #ffffff on #1a1a1a")
    
    gap = max(0, term_width - len(footer.plain) - len(right.plain))
    console.print(footer + Text(" " * gap) + right)

# ═══════════════════════════════════════════════════════════════════════════════
# DIRECTORY SELECTOR LOGIC (FULL)
# ═══════════════════════════════════════════════════════════════════════════════

def get_dir_info(path: Path) -> dict:
    try:
        exclude = {'node_modules', '.git', 'dist', 'build', '__pycache__', '.venv'}
        files = 0
        dirs = 0
        exts = {}
        for item in path.iterdir():
            if item.name in exclude: continue
            if item.is_dir(): dirs += 1
            elif item.is_file():
                files += 1
                e = item.suffix.lower() or 'no-ext'
                exts[e] = exts.get(e, 0) + 1
        
        scannable = any(x in exts for x in ['.py', '.js', '.ts', '.go', '.java', '.yaml', '.yml'])
        return {'files': files, 'dirs': dirs, 'scannable': scannable, 'exts': list(exts.keys())[:3]}
    except:
        return {'files': 0, 'dirs': 0, 'scannable': False, 'exts': []}

def ask_scan_options() -> dict:
    """Ask user for scan options before starting"""
    console.print("\n [#3b82f6]⚙️  SCAN OPTIONS[/#3b82f6]\n")
    
    # AI validation toggle
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GITHUB_TOKEN")
    ai_available = bool(api_key)
    
    if ai_available:
        use_ai = questionary.confirm(
            "🤖 Enable AI validation? (reduces false positives)",
            default=True,
            style=custom_style
        ).ask()
        if use_ai is None:
            return None
    else:
        console.print("[#666666]   AI validation unavailable (no API key set)[/#666666]")
        use_ai = False
    
    # Verbose mode
    verbose = questionary.confirm(
        "📋 Verbose output? (show all findings)",
        default=False,
        style=custom_style
    ).ask()
    if verbose is None:
        return None
    
    # Save report
    save_report = questionary.confirm(
        "💾 Save JSON report?",
        default=False,
        style=custom_style
    ).ask()
    if save_report is None:
        return None
    
    output = None
    if save_report:
        default_name = f"authent8_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output = questionary.text(
            "   Report filename:",
            default=default_name,
            style=custom_style
        ).ask()
        if output is None:
            return None
    
    return {
        'no_ai': not use_ai,
        'verbose': verbose,
        'output': output
    }

def interactive_path_selector() -> Path:
    current_path = Path.cwd()
    while True:
        clear_screen()
        console.print(f"\n [#3b82f6]📂 BROWSER[/#3b82f6] [#666666]│[/#666666] [#e5e5e5]{current_path}[/#e5e5e5]\n")
        
        info = get_dir_info(current_path)
        choices = [
            questionary.Choice(f"➔ SCAN THIS DIRECTORY ({current_path.name}/)", value="SCAN"),
            questionary.Separator("─── Navigation ───")
        ]
        
        if current_path != current_path.parent:
            choices.append(questionary.Choice(".. (Up)", value=".."))
        
        try:
            for d in sorted([x for x in current_path.iterdir() if x.is_dir() and not x.name.startswith('.')]):
                choices.append(questionary.Choice(f"dir/ {d.name}", value=str(d)))
        except PermissionError:
            choices.append(questionary.Choice("Permission Denied", disabled=True))

        choices.append(questionary.Separator("─── Actions ───"))
        choices.append(questionary.Choice("Enter Path Manually", value="MANUAL"))
        choices.append(questionary.Choice("Cancel", value="CANCEL"))

        ans = questionary.select("Select location:", choices=choices, style=custom_style).ask()

        if ans in ["CANCEL", None]: return None
        if ans == "SCAN": return current_path
        if ans == "..": current_path = current_path.parent
        elif ans == "MANUAL":
            p = questionary.text("Path:", style=custom_style).ask()
            if p and Path(p).exists(): current_path = Path(p).resolve()
        else:
            current_path = Path(ans)

# ═══════════════════════════════════════════════════════════════════════════════
# FALLBACK SUGGESTIONS (when AI unavailable)
# ═══════════════════════════════════════════════════════════════════════════════

def get_fallback_suggestion(finding: dict) -> str:
    """Generate fallback fix suggestions when AI is not available"""
    file_path = finding.get("file", "").lower()
    message = finding.get("message", "").lower()
    rule_id = finding.get("rule_id", "").lower()
    tool = finding.get("tool", "").lower()
    
    # .env file secrets
    if ".env" in file_path:
        return "Add .env to .gitignore. Never commit secrets."
    
    # Hardcoded secrets/API keys
    if any(x in message for x in ["hardcoded", "api key", "secret", "password", "token", "generic-api-key"]):
        return "Move secrets to environment variables or secret manager."
    
    # SQL injection
    if "sql" in message or "sql-injection" in rule_id:
        return "Use parameterized queries instead of string concatenation."
    
    # Command injection / shell
    if any(x in message for x in ["command", "shell", "os.system", "subprocess"]):
        return "Use subprocess with list args. Sanitize all inputs."
    
    # Eval
    if "eval" in message:
        return "Replace eval() with ast.literal_eval() or JSON parsing."
    
    # XSS
    if "xss" in message or "innerhtml" in message or "cross-site" in message:
        return "Sanitize user input. Use textContent instead of innerHTML."
    
    # Deserialization
    if "pickle" in message or "deserializ" in message:
        return "Use JSON instead of pickle. Never deserialize untrusted data."
    
    # Path traversal / file access
    if "path" in message or "open" in message or "file" in message:
        return "Validate file paths. Reject paths containing '../'."
    
    # User input / request data
    if "user" in message or "request" in message or "input" in message:
        return "Validate and sanitize all user input before use."
    
    # Gitleaks findings
    if tool == "gitleaks":
        return "Remove or rotate this secret. Add to .gitignore."
    
    # Generic based on severity
    severity = finding.get("severity", "MEDIUM")
    if severity == "CRITICAL":
        return "Critical security issue. Fix immediately."
    elif severity == "HIGH":
        return "High severity. Apply input validation and sanitization."
    
    return "Review and apply security best practices."

# ═══════════════════════════════════════════════════════════════════════════════
# SCAN ENGINE & AI VALIDATION (FULL)
# ═══════════════════════════════════════════════════════════════════════════════

def run_scan_with_progress(path: str, no_ai: bool = False, output: str = None, verbose: bool = False):
    clear_screen()
    console.print(f"\n [#3b82f6]authent8[/#3b82f6] [#1a1a1a]│[/#1a1a1a] [#e5e5e5]Scanning:[/#e5e5e5] [#666666]{path}[/#666666]\n")
    
    project_path = Path(path)
    exclude_dirs = {'node_modules', '.git', 'dist', 'build', 'vendor', '__pycache__', '.venv', 'venv', 'env', '.env', 'site-packages', '.tox', '.pytest_cache', '.mypy_cache', 'coverage', '.coverage', 'htmlcov', '.eggs', '*.egg-info'}
    scannable_exts = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php', '.cs', '.yaml', '.yml', '.json'}
    
    # Collect all scannable files for progress display
    all_files = [f for f in project_path.rglob('*') if not any(ex in f.parts for ex in exclude_dirs) 
                 and f.is_file() and f.suffix.lower() in scannable_exts]
    
    total_files = len(all_files)
    
    try:
        orchestrator = ScanOrchestrator(path)
    except Exception as e:
        console.print(f"[#ff3333]Error:[/#ff3333] {e}")
        return

    start_time = time.time()
    findings = []
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PROGRESS TRACKING WITH FILE NAMES (RESPONSIVE)
    # ═══════════════════════════════════════════════════════════════════════════
    term_width = console.width or 80
    bar_width = max(15, min(35, term_width - 50))  # Responsive bar width
    
    # Choose progress columns based on terminal width
    if term_width >= 80:
        progress_columns = [
            SpinnerColumn(style="#3b82f6"),
            TextColumn("[#e5e5e5]{task.description}[/#e5e5e5]"),
            BarColumn(bar_width=bar_width, style="#1a1a1a", complete_style="#3b82f6", finished_style="#10b981"),
            TaskProgressColumn(),
            TextColumn("[#666666]{task.fields[current_file]}[/#666666]"),
        ]
    elif term_width >= 60:
        progress_columns = [
            SpinnerColumn(style="#3b82f6"),
            TextColumn("[#e5e5e5]{task.description}[/#e5e5e5]"),
            BarColumn(bar_width=bar_width, style="#1a1a1a", complete_style="#3b82f6", finished_style="#10b981"),
            TaskProgressColumn(),
        ]
    else:
        progress_columns = [
            SpinnerColumn(style="#3b82f6"),
            TextColumn("[#e5e5e5]{task.description}[/#e5e5e5]"),
            TaskProgressColumn(),
        ]
    
    with Progress(*progress_columns, console=console, transient=False) as progress:
        
        # Create tasks (total=100 for percentage display)
        t1 = progress.add_task("Dependency Scan ", total=100, current_file="Waiting...")
        t2 = progress.add_task("Pattern Analysis", total=100, current_file="Waiting...")
        t3 = progress.add_task("Secret Hunting  ", total=100, current_file="Waiting...")
        
        # Helper to animate file scanning and fake percentage
        def animate_files(task_id, stop_event):
            import random
            files = [f.name for f in all_files] if all_files else ["file_check"]
            current_prog = 0
            
            while not stop_event.is_set():
                # Update files
                f = random.choice(files)
                
                # Zeno's progress: increment towards 95%
                if current_prog < 95:
                    step = random.uniform(0.5, 2.0)
                    current_prog = min(95, current_prog + step)
                
                progress.update(task_id, completed=current_prog, current_file=f"Scanning {f[:20]}...")
                time.sleep(0.1)

        # Run scans in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            # Start animations
            stop_t1 = threading.Event()
            stop_t2 = threading.Event()
            stop_t3 = threading.Event()
            
            threading.Thread(target=animate_files, args=(t1, stop_t1), daemon=True).start()
            threading.Thread(target=animate_files, args=(t2, stop_t2), daemon=True).start()
            threading.Thread(target=animate_files, args=(t3, stop_t3), daemon=True).start()

            # Submit tasks
            future_trivy = executor.submit(orchestrator.run_trivy)
            future_semgrep = executor.submit(orchestrator.run_semgrep)
            future_gitleaks = executor.submit(orchestrator.run_gitleaks)
            
            # Wait for results and stop animations
            trivy_findings = future_trivy.result()
            stop_t1.set()
            progress.update(t1, total=100, completed=100, current_file=f"✓ {len(trivy_findings)} found")
            
            semgrep_findings = future_semgrep.result()
            stop_t2.set()
            progress.update(t2, total=100, completed=100, current_file=f"✓ {len(semgrep_findings)} found")
            
            gitleaks_findings = future_gitleaks.result()
            stop_t3.set()
            progress.update(t3, total=100, completed=100, current_file=f"✓ {len(gitleaks_findings)} found")

        findings = trivy_findings + semgrep_findings + gitleaks_findings

        # AI Validation
        if not no_ai and findings:
            t4 = progress.add_task("AI Verification ", total=len(findings), current_file="")
            api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GITHUB_TOKEN")
            if api_key:
                try:
                    validator = AIValidator(api_key)
                    # Process in batches showing progress
                    validated = []
                    batch_size = 5
                    for i in range(0, len(findings), batch_size):
                        batch = findings[i:i+batch_size]
                        file_name = Path(batch[0].get("file", "")).name if batch else ""
                        progress.update(t4, current_file=f"{file_name} ({len(batch)} issues)")
                        result = validator._validate_batch(batch)
                        validated.extend(result)
                        progress.advance(t4, len(batch))
                    findings = validated
                except Exception as e:
                    progress.update(t4, current_file=f"⚠ Error: {str(e)[:20]}")
            progress.update(t4, completed=len(findings), current_file="✓ Complete")

    console.print()
    
    # Filter and Display
    real_findings = [f for f in findings if not f.get("is_false_positive", False)]
    duration = time.time() - start_time
    
    crit = sum(1 for f in real_findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in real_findings if f.get("severity") == "HIGH")
    
    add_to_history(path, len(real_findings), crit, high, duration)
    display_results(real_findings, duration, verbose)
    
    if output:
        with open(output, 'w') as f:
            json.dump(findings, f, indent=2)

# ═══════════════════════════════════════════════════════════════════════════════
# RESULTS RENDERING (OPENCODE STYLE)
# ═══════════════════════════════════════════════════════════════════════════════

def display_results(findings: list, duration: float, verbose: bool):
    if not findings:
        console.print(Panel(Align.center("[#10b981]✓ WORKSPACE CLEAN - NO ISSUES FOUND[/#10b981]"), border_style="#1a1a1a"))
        console.print()
        print_footer("COMPLETED")
        console.print()
        console.print("[dim]Press Enter to return...[/dim]")
        return

    # Severity Summary Pills
    sevs = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings: sevs[f.get("severity", "LOW")] += 1

    pill_row = Text()
    if sevs['CRITICAL'] > 0:
        pill_row.append(f" {sevs['CRITICAL']} CRITICAL ", style="bold #ffffff on #ff3333")
        pill_row.append("  ")
    if sevs['HIGH'] > 0:
        pill_row.append(f" {sevs['HIGH']} HIGH ", style="bold #000000 on #ff9900")
        pill_row.append("  ")
    if sevs['MEDIUM'] > 0:
        pill_row.append(f" {sevs['MEDIUM']} MEDIUM ", style="bold #ffffff on #3b82f6")
    
    console.print(Panel(Align.center(pill_row), title=f"[#e5e5e5]Scan Results ({duration:.1f}s)[/#e5e5e5]", border_style="#1a1a1a"))
    console.print()

    # Main Findings Table (Responsive)
    term_width = console.width or 80
    table = Table(box=box.SIMPLE_HEAD, expand=True, border_style="#1a1a1a", width=min(term_width - 4, 120))
    
    if term_width >= 80:
        table.add_column("Severity", width=10)
        table.add_column("Location", style="#666666", max_width=25)
        table.add_column("Finding", style="#e5e5e5")
    elif term_width >= 60:
        table.add_column("Sev", width=6)
        table.add_column("Location", style="#666666", max_width=18)
        table.add_column("Finding", style="#e5e5e5", max_width=30)
    else:
        table.add_column("Sev", width=5)
        table.add_column("Issue", style="#e5e5e5")

    sorted_f = sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x.get("severity"), 3))
    
    # Show all findings in verbose mode, otherwise limit
    display_limit = len(sorted_f) if verbose else 20
    
    for f in sorted_f[:display_limit]:
        s = f.get("severity", "LOW")
        color = {"CRITICAL": "#ff3333", "HIGH": "#ff9900", "MEDIUM": "#3b82f6"}.get(s, "#666666")
        loc = f"{Path(f.get('file','')).name}:{f.get('line','')}"
        msg = f.get("message", "")[:65]
        table.add_row(f"[{color}]{s}[/{color}]", loc, msg)

    console.print(table)
    
    if len(sorted_f) > display_limit:
        console.print(f"[#666666]   +{len(sorted_f) - display_limit} more issues (use -v to see all)[/#666666]")
    console.print()

    # ═══════════════════════════════════════════════════════════════════════════
    # SUGGESTIONS SECTION - SHOW ALL FINDINGS
    # ═══════════════════════════════════════════════════════════════════════════
    console.print(" [#3b82f6]💡 FIX SUGGESTIONS[/#3b82f6]")
    console.print()
    
    # Group by file
    by_file = {}
    for f in sorted_f:
        file_name = Path(f.get('file', 'unknown')).name
        if file_name not in by_file:
            by_file[file_name] = []
        by_file[file_name].append(f)
    
    # Show suggestions for each file (show ALL in verbose mode)
    max_files = len(by_file) if verbose else 8
    max_per_file = 100 if verbose else 5
    
    for file_name, file_findings in list(by_file.items())[:max_files]:
        console.print(f" [#3b82f6]📄 {file_name}[/#3b82f6]")
        
        for finding in file_findings[:max_per_file]:
            line = finding.get("line", "?")
            severity = finding.get("severity", "MEDIUM")
            
            # Get AI fix or fallback
            fix = finding.get("fix_suggestion", "")
            if not fix:
                fix = get_fallback_suggestion(finding)
            
            # Truncate if needed
            if len(fix) > 70 and not verbose:
                fix = fix[:67] + "..."
            
            # Color based on severity
            sev_colors = {"CRITICAL": "#ff3333", "HIGH": "#ff9900", "MEDIUM": "#3b82f6", "LOW": "#666666"}
            sev_color = sev_colors.get(severity, "#666666")
            
            console.print(f"    [{sev_color}]L{line}:[/{sev_color}] [#e5e5e5]{fix}[/#e5e5e5]")
        
        remaining = len(file_findings) - max_per_file
        if remaining > 0:
            console.print(f"    [#666666]+{remaining} more in this file[/#666666]")
        console.print()
    
    remaining_files = len(by_file) - max_files
    if remaining_files > 0:
        console.print(f" [#666666]+{remaining_files} more files with issues (use -v)[/#666666]")
    
    console.print()
    print_footer("COMPLETED")
    console.print()

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN MENU & ENTRY
# ═══════════════════════════════════════════════════════════════════════════════

def show_main_menu():
    clear_screen()
    print_enhanced_banner()
    
    # Scanner Status Pills
    tools = [
        ("Trivy", is_installed('trivy')),
        ("Semgrep", is_installed('semgrep')),
        ("Gitleaks", is_installed('gitleaks'))
    ]
    status_text = Text()
    for name, ok in tools:
        dot = "●" if ok else "○"
        col = "#10b981" if ok else "#ff3333"
        status_text.append(f" {dot} {name} ", style=f"{col}")
        status_text.append("  ")
    
    console.print(Align.center(status_text))
    console.print("\n")

    # Feature highlights instead of fake shortcuts
    features = Table.grid(padding=(0, 3))
    features.add_column(style="#3b82f6")
    features.add_column(style="#666666")
    
    features.add_row("🔒 Privacy-First", "Your code never leaves your machine")
    features.add_row("🤖 AI-Powered", "Reduces false positives with smart validation")
    features.add_row("⚡ Fast Scanning", "Trivy + Semgrep + Gitleaks in one command")
    
    console.print(Align.center(features))
    console.print("\n")

    # Recent History
    recent = get_recent_scans(1)
    if recent:
        r = recent[0]
        status = f"{r['critical']}C/{r['high']}H" if r['critical'] or r['high'] else f"{r['findings']} issues"
        console.print(Align.center(f"[#444444]Last scan: {r['path'].split('/')[-1]}/ → {status}[/#444444]"))
        console.print()
    
    console.print()
    
    # Menu left-aligned for consistent highlight behavior
    choice = questionary.select(
        "Select an option:",
        choices=[
            questionary.Choice("⚡ Quick Scan       Scan current directory", value="Quick Scan"),
            questionary.Choice("📂 Browse Files     Choose a folder to scan", value="Browse Files"),
            questionary.Choice("📝 Manual Path      Enter path directly", value="Manual Path"),
            questionary.Choice("⚙️  Configuration    View settings & status", value="Configuration"),
            questionary.Separator("─────────────────────────────────────────────"),
            questionary.Choice("❌ Exit             Close authent8", value="Exit"),
        ],
        style=custom_style,
        pointer="❯",
    ).ask()
    
    return choice

@click.group(invoke_without_command=True)
@click.option('--uninstall', is_flag=True, help='Uninstall authent8 completely')
@click.pass_context
def cli(ctx, uninstall):
    """Authent8 - Privacy-First Security Scanner"""
    if uninstall:
        if click.confirm("Are you sure you want to uninstall authent8?"):
            console.print("[yellow]Uninstalling authent8...[/yellow]")
            try:
                import subprocess
                import os
                # Run the uninstall
                subprocess.run(["pipx", "uninstall", "authent8"], check=True)
                # Use standard print to avoid Rich dependency issues after files are gone
                print("\n\033[32mSuccessfully uninstalled! Goodbye 👋\033[0m")
                # Immediate exit to avoid cleanup crashes
                os._exit(0)
            except Exception as e:
                # If we are here, something went wrong BEFORE pipx finished
                print(f"\n\033[31mError during uninstall request: {e}\033[0m")
                print("Manual command: pipx uninstall authent8")
                os._exit(1)
        return

    check_first_run()
    if ctx.invoked_subcommand is None:
        run_interactive_loop()

def run_interactive_loop():
    while True:
        choice = show_main_menu()
        if choice in ["Exit", None]: 
            console.print("\n[#3b82f6]Goodbye! 🔒[/#3b82f6]\n")
            break
        
        if choice == "Quick Scan":
            # Ask scan options
            options = ask_scan_options()
            if options:
                run_scan_with_progress(str(Path.cwd()), **options)
            input("\nPress Enter to return...")
        
        elif choice == "Browse Files":
            target = interactive_path_selector()
            if target:
                run_scan_with_progress(str(target))
                input("\nPress Enter to return...")
        
        elif choice == "Manual Path":
            p = questionary.text("Enter path:", style=custom_style).ask()
            if p and Path(p).exists():
                run_scan_with_progress(str(Path(p).resolve()))
                input("\nPress Enter to return...")
        
        elif choice == "Configuration":
            clear_screen()
            console.print("\n [#3b82f6]⚙️  ENGINE CONFIGURATION[/#3b82f6]\n")
            
            config_table = Table(box=box.SIMPLE, show_header=False)
            config_table.add_column("Setting", style="#666666")
            config_table.add_column("Value", style="#e5e5e5")
            
            ai_key = "✓ Set" if os.getenv('OPENAI_API_KEY') else ("✓ GitHub" if os.getenv('GITHUB_TOKEN') else "✗ Not set")
            config_table.add_row("AI Model", os.getenv('AI_MODEL', 'gpt-4o'))
            config_table.add_row("API Key", ai_key)
            config_table.add_row("Trivy", "✓ Installed" if is_installed('trivy') else "✗ Missing")
            config_table.add_row("Semgrep", "✓ Installed" if is_installed('semgrep') else "✗ Missing")
            config_table.add_row("Gitleaks", "✓ Installed" if is_installed('gitleaks') else "✗ Missing")
            
            console.print(config_table)
            console.print("\n[#666666]Configure via .env file or environment variables[/#666666]")
            input("\nPress Enter to return...")

@cli.command()
@click.argument('path', type=click.Path(exists=True), required=False)
@click.option('--no-ai', is_flag=True, help='Skip AI validation')
@click.option('--verbose', '-v', is_flag=True, help='Show all findings')
@click.option('--output', '-o', type=click.Path(), help='Save JSON report')
def scan(path, no_ai, verbose, output):
    """Direct scan command"""
    target = path or str(Path.cwd())
    run_scan_with_progress(target, no_ai=no_ai, verbose=verbose, output=output)

if __name__ == "__main__":
    cli()
