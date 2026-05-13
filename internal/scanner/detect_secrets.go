package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AshishOP/authent8/internal/ignore"
)

// DetectSecretsScanner wraps the detect-secrets scanner.
type DetectSecretsScanner struct{}

func (d *DetectSecretsScanner) Name() string          { return "detect-secrets" }
func (d *DetectSecretsScanner) RequiresInternet() bool { return false }

func (d *DetectSecretsScanner) Scan(ctx context.Context, projectPath string, ignorePatterns []string) ([]Finding, error) {
	cmd := exec.CommandContext(ctx, "detect-secrets",
		"scan",
		"--all-files",
		projectPath,
	)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			errMsg := strings.TrimSpace(string(exitErr.Stderr))
			if errMsg == "" {
				errMsg = string(out)
			}
			return nil, fmt.Errorf("detect-secrets failed: %s", Truncate(errMsg, 300))
		}
		return nil, fmt.Errorf("detect-secrets: %w", err)
	}

	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, nil
	}

	var data detectSecretsOutput
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, fmt.Errorf("detect-secrets returned invalid JSON: %w", err)
	}

	findings := parseDetectSecretsResults(data)

	// Apply ignore filters
	if len(ignorePatterns) > 0 {
		var filtered []Finding
		for _, f := range findings {
			filePath := filepath.Join(projectPath, f.File)
			if !ignore.ShouldIgnore(filePath, projectPath, ignorePatterns) {
				filtered = append(filtered, f)
			}
		}
		return filtered, nil
	}

	return findings, nil
}

// --- detect-secrets JSON structures ---

type detectSecretsOutput struct {
	Results map[string][]detectSecretsItem `json:"results"`
}

type detectSecretsItem struct {
	Type       string `json:"type"`
	LineNumber int    `json:"line_number"`
}

func parseDetectSecretsResults(data detectSecretsOutput) []Finding {
	var findings []Finding

	for filePath, secrets := range data.Results {
		for _, item := range secrets {
			findings = append(findings, Finding{
				Tool:        "detect-secrets",
				Type:        "secret",
				Severity:    SeverityCritical,
				RuleID:      item.Type,
				Title:       fmt.Sprintf("Potential secret detected (%s)", item.Type),
				Description: "Potential secret detected by detect-secrets",
				Message:     fmt.Sprintf("Potential secret detected: %s", item.Type),
				File:        filePath,
				Line:        item.LineNumber,
			})
		}
	}

	return findings
}
