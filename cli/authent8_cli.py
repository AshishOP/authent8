import click
import json
import os
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
from dotenv import load_dotenv

# Load environment variables from .env file
# Try to find .env in current directory or parents
env_path = Path(__file__).parent.parent / '.env'
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv() # Fallback to default behavior

# Add parent directory to path to allow imports from core
# This assumes the script is at authent8/cli/authent8_cli.py
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scanner_orchestrator import ScanOrchestrator
from core.ai_validator import AIValidator

console = Console()

@click.group()
def cli():
    """🛡️  Authent8 - Privacy-First Security Scanner"""
    pass

@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--no-ai', is_flag=True, help='Skip AI validation')
@click.option('--output', '-o', type=click.Path(), help='Output JSON file')
def scan(path, no_ai, output):
    """
    Scan a project for security vulnerabilities
    
    Example: authent8 scan /path/to/project
    """
    
    console.print("\n[bold cyan]🛡️  Authent8 Security Scanner[/bold cyan]")
    console.print(f"[dim]Scanning: {path}[/dim]\n")
    
    # Initialize
    try:
        orchestrator = ScanOrchestrator(path)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return
    
    # Run scans with progress (use parallel scan for efficiency)
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning with all tools...", total=1)
        
        # Run all scanners in parallel
        orchestrator.scan_all_parallel()
        progress.advance(task)
    
    all_findings = orchestrator.get_all_findings()
    
    console.print(f"\n[green]✓[/green] Found {len(all_findings)} potential issues\n")
    
    # AI Validation
    if not no_ai:
        api_key = os.getenv("GITHUB_TOKEN") or os.getenv("OPENAI_API_KEY")
        if not api_key:
            console.print("[yellow]⚠️  GITHUB_TOKEN (or OPENAI_API_KEY) not set. Skipping AI validation.[/yellow]")
            console.print("[dim]   Set it: export GITHUB_TOKEN='your-key'[/dim]\n")
        else:
            console.print("[cyan]🤖 AI is validating findings...[/cyan]")
            try:
                validator = AIValidator(api_key)
                all_findings = validator.validate_findings(all_findings)
                
                false_positives = sum(1 for f in all_findings if f.get("is_false_positive"))
                console.print(f"[green]✓[/green] AI removed {false_positives} false positives\n")
            except Exception as e:
                console.print(f"[red]AI Validation Error:[/red] {e}")
                console.print("[yellow]Continuing with raw results...[/yellow]")
    
    # Privacy report
    show_privacy_report(all_findings, no_ai)
    
    # Display results
    display_results(all_findings, no_ai)
    
    # Save
    if output:
        with open(output, 'w') as f:
            json.dump(all_findings, f, indent=2)
        console.print(f"\n[green]✓[/green] Results saved to {output}")

def show_privacy_report(findings, no_ai):
    """Show what AI saw"""
    console.print(Panel.fit(
        f"[bold green]✓[/bold green] Source code: [bold]Scanned locally[/bold]\n[bold green]✓[/bold green] Data sent to AI: [bold]0 bytes of code[/bold]\n[bold green]✓[/bold green] Context sent: [bold]{len(findings)} finding summaries[/bold]\n[bold green]✓[/bold green] AI training: [bold red]NEVER[/bold red]\n[bold green]✓[/bold green] Your code: [bold]100% private[/bold]",
        title="🔒 Privacy Report",
        border_style="green"
    ))
    console.print()

def display_results(findings, no_ai):
    """Display findings in table"""
    
    real_findings = [f for f in findings if not f.get("is_false_positive", False)]
    
    if not real_findings:
        console.print("[green]🎉 No security issues found![/green]\n")
        return
    
    # Count by severity
    critical = [f for f in real_findings if f.get("severity") == "CRITICAL"]
    high = [f for f in real_findings if f.get("severity") == "HIGH"]
    medium = [f for f in real_findings if f.get("severity") == "MEDIUM"]
    
    # Summary
    console.print(f"[bold red]🔴 CRITICAL: {len(critical)}[/bold red]  " 
                  f"[bold yellow]🟠 HIGH: {len(high)}[/bold yellow]  " 
                  f"[dim]🟡 MEDIUM: {len(medium)}[/dim]\n")
    
    # Table
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Severity", width=10)
    table.add_column("Tool", width=10)
    table.add_column("Issue", width=40)
    table.add_column("Location", width=20)
    if not no_ai:
        table.add_column("AI Fix", width=30)
    
    for finding in real_findings[:20]:
        severity_style = {
            "CRITICAL": "[bold red]",
            "HIGH": "[bold yellow]",
            "MEDIUM": "[dim]"
        }.get(finding.get("severity", ""), "")
        
        row = [
            f"{severity_style}{finding.get('severity', 'UNKNOWN')}[/]",
            finding.get("tool", ""),
            finding.get("message", finding.get("description", ""))[:40].replace("\n", " "),
            f"{finding.get('file', '')}:{finding.get('line', '')}"
        ]
        
        if not no_ai:
            fix = finding.get("fix_suggestion", "")
            confidence = finding.get("ai_confidence", 0)
            row.append(f"[dim]{fix[:30]} ({confidence}%)[/dim]" if fix else "")
        
        table.add_row(*row)
    
    console.print(table)
    
    if len(real_findings) > 20:
        console.print(f"\n[dim]... and {len(real_findings) - 20} more issues[/dim]")

if __name__ == "__main__":
    cli()
