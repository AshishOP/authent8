package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// CheckovScanner wraps the Checkov IaC security scanner.
type CheckovScanner struct{}

func (c *CheckovScanner) Name() string          { return "checkov" }
func (c *CheckovScanner) RequiresInternet() bool { return false }

func (c *CheckovScanner) Scan(ctx context.Context, projectPath string, _ []string) ([]Finding, error) {
	cmd := exec.CommandContext(ctx, "checkov",
		"-d", projectPath,
		"--output", "json",
		"--quiet",
	)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Checkov returns 1 when findings exist
			if exitErr.ExitCode() == 1 && len(out) > 0 {
				// Parse output below
			} else {
				errMsg := strings.TrimSpace(string(exitErr.Stderr))
				if errMsg == "" {
					errMsg = string(out)
				}
				return nil, fmt.Errorf("checkov failed: %s", Truncate(errMsg, 300))
			}
		} else {
			return nil, fmt.Errorf("checkov: %w", err)
		}
	}

	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return nil, nil
	}

	// Try full JSON parse first
	var data checkovOutput
	if err := json.Unmarshal([]byte(raw), &data); err == nil {
		return parseCheckovResults(data), nil
	}

	// Checkov may emit multiple JSON docs; parse line-by-line
	var findings []Finding
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var lineData checkovOutput
		if err := json.Unmarshal([]byte(line), &lineData); err == nil {
			findings = append(findings, parseCheckovResults(lineData)...)
		}
	}
	return findings, nil
}

// --- Checkov JSON structures ---

type checkovOutput struct {
	Results checkovResults `json:"results"`
}

type checkovResults struct {
	FailedChecks []checkovCheck `json:"failed_checks"`
}

type checkovCheck struct {
	CheckID       string `json:"check_id"`
	CheckName     string `json:"check_name"`
	FilePath      string `json:"file_path"`
	Severity      string `json:"severity"`
	FileLineRange []int  `json:"file_line_range"`
}

func parseCheckovResults(data checkovOutput) []Finding {
	var findings []Finding

	for _, item := range data.Results.FailedChecks {
		severity := NormalizeSeverity(item.Severity)

		line := 0
		if len(item.FileLineRange) > 0 {
			line = item.FileLineRange[0]
		}

		findings = append(findings, Finding{
			Tool:        "checkov",
			Type:        "iac",
			Severity:    severity,
			RuleID:      item.CheckID,
			Title:       Truncate(item.CheckName, 200),
			Description: Truncate(item.CheckName, 500),
			Message:     Truncate(item.CheckName, 200),
			File:        item.FilePath,
			Line:        line,
		})
	}

	return findings
}
