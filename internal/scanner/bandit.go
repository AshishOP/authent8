package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// BanditScanner wraps the Bandit Python-specific SAST scanner.
type BanditScanner struct{}

func (b *BanditScanner) Name() string          { return "bandit" }
func (b *BanditScanner) RequiresInternet() bool { return false }

// banditExcludeDirs lists directories skipped during Bandit scans.
var banditExcludeDirs = []string{
	"node_modules", ".git", "dist", "build", "vendor", "__pycache__",
	".venv", "venv", "env", ".tox", "coverage", ".nyc_output",
	"site-packages", ".cache", "tmp", ".tmp",
}

func (b *BanditScanner) Scan(ctx context.Context, projectPath string, _ []string) ([]Finding, error) {
	excludeStr := strings.Join(banditExcludeDirs, ",")

	cmd := exec.CommandContext(ctx, "bandit",
		"-r", projectPath,
		"-f", "json",
		"-x", excludeStr,
		"-ll",   // Medium+ severity
		"-q",    // Quiet mode
	)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Bandit returns 1 when issues are found — that's normal
			if exitErr.ExitCode() == 1 && len(out) > 0 {
				// Parse the output below
			} else {
				errMsg := strings.TrimSpace(string(exitErr.Stderr))
				if errMsg == "" {
					errMsg = string(out)
				}
				return nil, fmt.Errorf("bandit failed: %s", Truncate(errMsg, 300))
			}
		} else {
			return nil, fmt.Errorf("bandit: %w", err)
		}
	}

	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, nil
	}

	var data banditOutput
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, fmt.Errorf("bandit returned invalid JSON: %w", err)
	}

	return parseBanditResults(data), nil
}

// --- Bandit JSON structures ---

type banditOutput struct {
	Results []banditResult `json:"results"`
}

type banditResult struct {
	TestID        string `json:"test_id"`
	IssueSeverity string `json:"issue_severity"`
	IssueText     string `json:"issue_text"`
	Filename      string `json:"filename"`
	LineNumber    int    `json:"line_number"`
	Code          string `json:"code"`
}

func parseBanditResults(data banditOutput) []Finding {
	var findings []Finding

	for _, r := range data.Results {
		severity := SeverityMedium
		switch strings.ToUpper(r.IssueSeverity) {
		case "HIGH":
			severity = SeverityHigh
		case "MEDIUM":
			severity = SeverityMedium
		case "LOW":
			severity = SeverityLow
		}

		findings = append(findings, Finding{
			Tool:        "bandit",
			Type:        "sast",
			Severity:    severity,
			RuleID:      r.TestID,
			Title:       Truncate(r.IssueText, 200),
			Description: Truncate(r.IssueText, 500),
			Message:     Truncate(r.IssueText, 200),
			File:        r.Filename,
			Line:        r.LineNumber,
			CodeSnippet: Truncate(r.Code, 300),
		})
	}

	return findings
}
