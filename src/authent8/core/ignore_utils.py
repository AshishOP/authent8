"""Shared ignore-pattern loading and matching utilities."""

from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable, List

DEFAULT_IGNORE_PATTERNS = [
    "node_modules",
    ".git",
    "dist",
    "build",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    ".next",
    ".cache",
    ".tmp",
    "site-packages",
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.log",
    "package-lock.json",
]


def load_ignore_patterns(project_path: Path) -> List[str]:
    """Load defaults + .a8ignore entries."""
    patterns = list(DEFAULT_IGNORE_PATTERNS)
    ignore_file = project_path / ".a8ignore"
    if ignore_file.exists():
        try:
            with open(ignore_file, "r", encoding="utf-8") as file:
                for line in file:
                    entry = line.strip()
                    if entry and not entry.startswith("#"):
                        patterns.append(entry.rstrip("/"))
        except OSError:
            pass

    # preserve order while deduplicating
    return list(dict.fromkeys(patterns))


def should_ignore_path(path: Path, project_path: Path, patterns: Iterable[str]) -> bool:
    """Match a path against ignore patterns using basename, segment, and glob checks."""
    try:
        rel_path = path.resolve().relative_to(project_path.resolve())
        rel = rel_path.as_posix()
    except Exception:
        rel = path.as_posix()

    name = path.name
    parts = rel.split("/")

    for raw in patterns:
        pattern = str(raw).strip().rstrip("/")
        if not pattern:
            continue

        normalized = pattern.replace("\\", "/")
        is_glob = any(ch in normalized for ch in "*?[]")

        if is_glob:
            if fnmatch(rel, normalized) or fnmatch(name, normalized):
                return True
            continue

        if normalized in parts:
            return True
        if rel == normalized or rel.startswith(normalized + "/"):
            return True
        if name == normalized:
            return True

    return False
