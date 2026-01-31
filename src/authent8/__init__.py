"""
Authent8 - Privacy-First Security Scanner

A security scanning tool that combines Trivy, Semgrep, and Gitleaks
with AI-powered validation to detect vulnerabilities while keeping
your code local.
"""

__version__ = "1.0.0"
__author__ = "Authent8 Team"

from authent8.core.scanner_orchestrator import ScanOrchestrator
from authent8.core.ai_validator import AIValidator

__all__ = [
    "ScanOrchestrator",
    "AIValidator",
    "__version__",
]
