// Package ignore handles .a8ignore file loading and path matching.
package ignore

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// DefaultPatterns are always excluded from scans.
var DefaultPatterns = []string{
	".env", ".env.*", ".authent8_fp.json", "authent8_report_*.json",
	"node_modules", ".git", "dist", "build", "vendor",
	"__pycache__", ".venv", "venv", ".next", ".cache", ".tmp",
	"site-packages", "*.min.js", "*.min.css", "*.map", "*.log",
	"package-lock.json",
}

// LoadPatterns reads default patterns + .a8ignore entries from the project root.
func LoadPatterns(projectPath string) []string {
	// Start with defaults (copy to avoid mutation)
	patterns := make([]string, len(DefaultPatterns))
	copy(patterns, DefaultPatterns)

	seen := make(map[string]bool, len(patterns))
	for _, p := range patterns {
		seen[p] = true
	}

	// Load .a8ignore
	ignoreFile := filepath.Join(projectPath, ".a8ignore")
	f, err := os.Open(ignoreFile)
	if err != nil {
		return patterns
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry := strings.TrimRight(line, "/")
		if !seen[entry] {
			patterns = append(patterns, entry)
			seen[entry] = true
		}
	}

	return patterns
}

// ShouldIgnore checks if a path should be excluded based on ignore patterns.
// It checks the basename, path segments, and glob patterns.
func ShouldIgnore(path, projectPath string, patterns []string) bool {
	// Resolve to relative path
	rel, err := filepath.Rel(projectPath, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	name := filepath.Base(path)
	parts := strings.Split(rel, "/")

	for _, raw := range patterns {
		pattern := strings.TrimSpace(raw)
		pattern = strings.TrimRight(pattern, "/")
		if pattern == "" {
			continue
		}

		normalized := filepath.ToSlash(pattern)
		isGlob := strings.ContainsAny(normalized, "*?[]")

		if isGlob {
			// Try matching against full relative path and basename
			if matched, _ := filepath.Match(normalized, rel); matched {
				return true
			}
			if matched, _ := filepath.Match(normalized, name); matched {
				return true
			}
			continue
		}

		// Exact segment match
		for _, part := range parts {
			if part == normalized {
				return true
			}
		}
		// Full relative path match
		if rel == normalized || strings.HasPrefix(rel, normalized+"/") {
			return true
		}
		// Basename match
		if name == normalized {
			return true
		}
	}

	return false
}
