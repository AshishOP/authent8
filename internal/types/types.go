// Package types provides shared data structures used across all Authent8 packages.
// This package has NO dependencies on other internal packages to prevent import cycles.
package types

import "context"

// Finding represents a normalized security finding from any scanner.
type Finding struct {
	Tool            string `json:"tool"`
	Type            string `json:"type"`                         // "vulnerability", "sast", "secret", "iac"
	Severity        string `json:"severity"`                     // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	RuleID          string `json:"rule_id"`
	Title           string `json:"title"`
	Description     string `json:"description"`
	Message         string `json:"message"`
	File            string `json:"file"`
	Line            int    `json:"line"`
	CodeSnippet     string `json:"code_snippet,omitempty"`
	Package         string `json:"package,omitempty"`
	FixedVersion    string `json:"fixed_version,omitempty"`
	IsFalsePositive bool   `json:"is_false_positive"`
	AIConfidence    int    `json:"ai_confidence"`
	FixSuggestion   string `json:"fix_suggestion,omitempty"`
	AIReasoning     string `json:"ai_reasoning,omitempty"`
	Validated       bool   `json:"validated"`
}

// Scanner is the interface all scanner wrappers must implement.
type Scanner interface {
	Name() string
	Scan(ctx context.Context, projectPath string, ignorePatterns []string) ([]Finding, error)
	RequiresInternet() bool
}

// ScanSummary contains aggregate scan statistics.
type ScanSummary struct {
	TotalFindings   int               `json:"total_findings"`
	Suppressed      int               `json:"suppressed_findings"`
	ByTool          map[string]int    `json:"by_tool"`
	BySeverity      map[string]int    `json:"by_severity"`
	DurationSeconds float64           `json:"scan_duration_seconds"`
	Errors          map[string]string `json:"errors,omitempty"`
}

// Severity constants.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// NormalizeSeverity maps arbitrary severity strings to standard values.
func NormalizeSeverity(s string) string {
	switch s {
	case "CRITICAL", "critical":
		return SeverityCritical
	case "HIGH", "high", "ERROR", "error":
		return SeverityHigh
	case "MEDIUM", "medium", "WARNING", "warning":
		return SeverityMedium
	case "LOW", "low", "INFO", "info":
		return SeverityLow
	default:
		return SeverityMedium
	}
}

// Truncate returns s truncated to maxLen characters.
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
