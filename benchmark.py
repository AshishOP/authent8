#!/usr/bin/env python3
"""
Authent8 Accuracy Benchmark Tool
Measures precision, recall, F1 before/after changes
"""
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime

# Ground truth: Known vulnerabilities in tests/vulnerable-app/app.py
# Each tuple: (line_number, vulnerability_type, tool_expected)
GROUND_TRUTH = [
    # SQL Injection (lines 22, 23, 26)
    (22, "sql-injection", "semgrep"),
    (23, "sql-injection", "semgrep"),
    (26, "sql-injection", "semgrep"),
    
    # Command Injection (lines 41, 43, 44)
    (41, "command-injection", "semgrep"),
    (43, "command-injection", "semgrep"),
    (44, "info-disclosure", "semgrep"),  # directly-returned-format
    
    # Code Injection - eval (lines 49, 51)
    (49, "eval-injection", "semgrep"),
    (51, "eval-injection", "semgrep"),
    
    # Deserialization (line 59)
    (59, "insecure-deserialization", "semgrep"),
    
    # Weak crypto MD5 (line 67)
    (67, "weak-crypto", "semgrep"),
    
    # XSS - render_template_string (line 75)
    (75, "xss", "semgrep"),
    
    # Path Traversal (lines 80, 82)
    (80, "path-traversal", "semgrep"),
    (82, "path-traversal", "semgrep"),
    
    # Debug mode (line 97)
    (97, "debug-mode", "semgrep"),
]

# Lines that should NOT be flagged (false positive indicators)
SAFE_LINES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]  # Imports, comments

HISTORY_FILE = Path(__file__).parent / ".benchmark_history.json"

def load_history():
    """Load benchmark history"""
    if HISTORY_FILE.exists():
        with open(HISTORY_FILE) as f:
            return json.load(f)
    return []

def save_history(history):
    """Save benchmark history"""
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history[-20:], f, indent=2)  # Keep last 20

def run_scan(target_path: str, use_ai: bool = False) -> list:
    """Run authent8 scan and return findings"""
    output_file = Path(__file__).parent / "bench_results.json"
    cmd = [sys.executable, "-m", "authent8", "scan", target_path, "-o", str(output_file)]
    if not use_ai:
        cmd.append("--no-ai")
    
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=120, cwd=Path(__file__).parent, text=True)
        if result.returncode != 0:
            print(f"⚠️  Scan output: {result.stderr[:200] if result.stderr else 'no error'}")
        
        if output_file.exists():
            with open(output_file) as f:
                return json.load(f)
        else:
            print(f"⚠️  Output file not created. Trying direct scan...")
            # Fallback: run orchestrator directly from local core/
            sys.path.insert(0, str(Path(__file__).parent / "core"))
            from scanner_orchestrator import ScanOrchestrator
            orch = ScanOrchestrator(target_path)
            return orch.run_trivy() + orch.run_semgrep() + orch.run_gitleaks()
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        return []

def calculate_metrics(findings: list, ground_truth: list) -> dict:
    """Calculate precision, recall, F1 score"""
    
    expected_lines = set(gt[0] for gt in ground_truth)
    
    # Get detected lines from findings (only from app.py)
    detected_lines = set()
    for f in findings:
        file_name = f.get("file", "")
        if "app.py" in file_name:
            line = f.get("line", 0)
            if line:
                detected_lines.add(line)
    
    # Calculate metrics
    true_positives = len(expected_lines & detected_lines)
    false_negatives = len(expected_lines - detected_lines)
    false_positives = len(detected_lines - expected_lines)
    
    # Precision: Of what we detected, how many are real?
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    
    # Recall: Of real vulnerabilities, how many did we catch?
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    
    # F1: Harmonic mean
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "total_expected": len(expected_lines),
        "total_detected": len(detected_lines),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": round(precision * 100, 1),
        "recall": round(recall * 100, 1),
        "f1_score": round(f1 * 100, 1),
        "detected_lines": sorted(detected_lines),
        "missed_lines": sorted(expected_lines - detected_lines),
    }

def print_metrics(metrics: dict, label: str = "Current"):
    """Pretty print metrics"""
    print(f"\n{'='*60}")
    print(f"📊 {label} Accuracy Metrics")
    print('='*60)
    
    print(f"\n  Expected vulnerabilities: {metrics['total_expected']}")
    print(f"  Detected issues:          {metrics['total_detected']}")
    print()
    print(f"  ✅ True Positives:  {metrics['true_positives']}")
    print(f"  ❌ False Positives: {metrics['false_positives']}")
    print(f"  ⚠️  Missed (FN):     {metrics['false_negatives']}")
    print()
    print(f"  📈 Precision: {metrics['precision']}%  (of detected, % real)")
    print(f"  📈 Recall:    {metrics['recall']}%  (of real, % caught)")
    print(f"  📈 F1 Score:  {metrics['f1_score']}%  (overall accuracy)")
    
    if metrics['missed_lines']:
        print(f"\n  ⚠️  Missed lines: {metrics['missed_lines']}")

def compare_with_previous(current: dict, previous: dict = None):
    """Show improvement/regression vs previous run"""
    if not previous:
        return
    
    print(f"\n{'─'*60}")
    print("📊 Comparison with Previous Run")
    print('─'*60)
    
    for metric in ['precision', 'recall', 'f1_score']:
        curr = current[metric]
        prev = previous[metric]
        diff = curr - prev
        
        if diff > 0:
            emoji = "📈"
            color = "\033[92m"  # Green
        elif diff < 0:
            emoji = "📉"
            color = "\033[91m"  # Red
        else:
            emoji = "➡️"
            color = "\033[0m"   # Reset
        
        reset = "\033[0m"
        metric_name = metric.replace('_', ' ').title()
        print(f"  {emoji} {metric_name}: {prev}% → {color}{curr}%{reset} ({diff:+.1f}%)")

def main():
    """Run benchmark"""
    print("🎯 Authent8 Accuracy Benchmark")
    print("="*60)
    
    # Target path
    target = Path(__file__).parent / "tests" / "vulnerable-app"
    if not target.exists():
        target = Path(__file__).parent.parent / "tests" / "vulnerable-app"
    
    if not target.exists():
        print(f"❌ Test target not found: {target}")
        print("   Make sure tests/vulnerable-app/app.py exists")
        sys.exit(1)
    
    print(f"📁 Target: {target}")
    print(f"📋 Ground truth: {len(GROUND_TRUTH)} known vulnerabilities")
    
    # Run scan
    print("\n🔍 Running scan (this may take ~30s)...")
    findings = run_scan(str(target), use_ai=False)
    
    if not findings:
        print("❌ No findings returned. Check if authent8 is installed correctly.")
        sys.exit(1)
    
    # Calculate metrics
    metrics = calculate_metrics(findings, GROUND_TRUTH)
    metrics["timestamp"] = datetime.now().isoformat()
    metrics["total_findings"] = len(findings)
    
    # Load history and compare
    history = load_history()
    previous = history[-1] if history else None
    
    # Print results
    print_metrics(metrics)
    compare_with_previous(metrics, previous)
    
    # Save to history
    history.append(metrics)
    save_history(history)
    
    print(f"\n✅ Results saved to {HISTORY_FILE}")
    print(f"   Run this again after changes to see improvement!\n")
    
    return metrics

if __name__ == "__main__":
    main()
