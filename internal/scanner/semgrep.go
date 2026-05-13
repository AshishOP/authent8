package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"unicode"
)

// SemgrepScanner wraps the Semgrep SAST scanner with industry-standard rule packs.
type SemgrepScanner struct{}

func (s *SemgrepScanner) Name() string          { return "semgrep" }
func (s *SemgrepScanner) RequiresInternet() bool { return true }

// semgrepRulePacks lists the remote rule packs used for scanning.
// These are industry-standard rulesets covering OWASP Top 10, CWE Top 25, and more.
var semgrepRulePacks = []string{
	"p/security-audit",
	"p/owasp-top-ten",
	"p/cwe-top-25",
	"p/secrets",
	"p/python",
	"p/flask",
	"p/django",
	"p/jwt",
	"p/sql-injection",
	"p/command-injection",
	"p/xss",
	"p/insecure-transport",
	"p/docker",
	"p/kubernetes",
	"p/terraform",
	"p/aws-security",
	"p/react",
	"p/typescript",
}

func (s *SemgrepScanner) Scan(ctx context.Context, projectPath string, ignorePatterns []string) ([]Finding, error) {
	// Write embedded custom rules to temp file
	tmpDir, err := os.MkdirTemp("", "authent8-semgrep-*")
	if err != nil {
		return nil, fmt.Errorf("semgrep: failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	customRulesPath, err := writeEmbeddedConfig("custom_rules.yml", tmpDir)
	if err != nil {
		// Non-fatal: proceed without custom rules
		customRulesPath = ""
	}

	// Build exclude args
	var excludeArgs []string
	seen := make(map[string]bool)
	for _, p := range ignorePatterns {
		if !seen[p] {
			excludeArgs = append(excludeArgs, "--exclude", p)
			seen[p] = true
		}
	}

	// Build command with all rule packs
	args := make([]string, 0, 60)
	for _, pack := range semgrepRulePacks {
		args = append(args, "--config", pack)
	}
	if customRulesPath != "" {
		args = append(args, "--config", customRulesPath)
	}
	args = append(args,
		"--json",
		"--quiet",
		"--no-git-ignore",
		"--metrics", "off",
		"--project-root", projectPath,
	)
	args = append(args, excludeArgs...)
	args = append(args, projectPath)

	cmd := exec.CommandContext(ctx, "semgrep", args...)
	out, err := cmd.Output()

	// Handle non-zero exit: Semgrep returns 1 when findings exist, 2 on partial failures.
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Try parsing output even on non-zero exit (semgrep often returns partial results)
			if parsed := tryParseSemgrepOutput(out); parsed != nil {
				return parsed, nil
			}

			errMsg := strings.TrimSpace(string(exitErr.Stderr))
			lowerErr := strings.ToLower(errMsg)

			// If remote rule download failed, fallback to local custom rules only
			if (strings.Contains(lowerErr, "failed to download") ||
				strings.Contains(lowerErr, "could not download") ||
				strings.Contains(lowerErr, "network")) && customRulesPath != "" {

				return s.scanLocalOnly(ctx, projectPath, customRulesPath, excludeArgs)
			}

			return nil, fmt.Errorf("semgrep failed: %s", Truncate(errMsg, 300))
		}
		return nil, fmt.Errorf("semgrep: %w", err)
	}

	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, nil
	}

	var data semgrepOutput
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, fmt.Errorf("semgrep returned invalid JSON: %w", err)
	}

	return parseSemgrepResults(data), nil
}

// scanLocalOnly falls back to custom rules only when remote packs fail to download.
func (s *SemgrepScanner) scanLocalOnly(ctx context.Context, projectPath, customRulesPath string, excludeArgs []string) ([]Finding, error) {
	args := []string{
		"--config", customRulesPath,
		"--json",
		"--quiet",
		"--no-git-ignore",
		"--metrics", "off",
		"--project-root", projectPath,
	}
	args = append(args, excludeArgs...)
	args = append(args, projectPath)

	cmd := exec.CommandContext(ctx, "semgrep", args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if parsed := tryParseSemgrepOutput(out); parsed != nil {
				return parsed, nil
			}
			errMsg := strings.TrimSpace(string(exitErr.Stderr))
			return nil, fmt.Errorf("semgrep failed (local fallback): %s", Truncate(errMsg, 300))
		}
		return nil, fmt.Errorf("semgrep (local fallback): %w", err)
	}

	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, nil
	}

	var data semgrepOutput
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, fmt.Errorf("semgrep returned invalid JSON: %w", err)
	}
	return parseSemgrepResults(data), nil
}

func tryParseSemgrepOutput(out []byte) []Finding {
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil
	}
	var data semgrepOutput
	if err := json.Unmarshal(out, &data); err != nil {
		return nil
	}
	if len(data.Results) == 0 {
		return nil
	}
	return parseSemgrepResults(data)
}

// --- Semgrep JSON structures ---

type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string         `json:"check_id"`
	Path    string         `json:"path"`
	Start   semgrepPos     `json:"start"`
	End     semgrepPos     `json:"end"`
	Extra   semgrepExtra   `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Lines    string `json:"lines"`
}

func parseSemgrepResults(data semgrepOutput) []Finding {
	var findings []Finding

	for _, r := range data.Results {
		code := sanitizeText(Truncate(r.Extra.Lines, 300))
		message := sanitizeText(r.Extra.Message)

		// Map semgrep severity to standard
		severity := SeverityMedium
		switch strings.ToUpper(r.Extra.Severity) {
		case "ERROR":
			severity = SeverityHigh
		case "WARNING":
			severity = SeverityMedium
		case "INFO":
			severity = SeverityLow
		}

		findings = append(findings, Finding{
			Tool:        "semgrep",
			Type:        "sast",
			Severity:    severity,
			RuleID:      sanitizeText(r.CheckID),
			Title:       Truncate(message, 200),
			Description: Truncate(message, 500),
			Message:     Truncate(message, 200),
			File:        r.Path,
			Line:        r.Start.Line,
			CodeSnippet: code,
		})
	}

	return findings
}

// sanitizeText replaces common Unicode characters with ASCII equivalents
// and strips remaining non-ASCII characters to prevent encoding issues.
func sanitizeText(s string) string {
	if s == "" {
		return ""
	}
	replacements := map[rune]string{
		'\u2026': "...",
		'\u2019': "'",
		'\u2018': "'",
		'\u201c': "\"",
		'\u201d': "\"",
		'\u2014': "--",
		'\u2013': "-",
		'\u00a0': " ",
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if repl, ok := replacements[r]; ok {
			b.WriteString(repl)
		} else if r < 128 && unicode.IsPrint(r) || r == '\n' || r == '\t' {
			b.WriteRune(r)
		}
		// Skip non-ASCII characters not in the replacement map
	}
	return b.String()
}
