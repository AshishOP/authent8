package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// OSVScanner wraps the OSV-Scanner vulnerability scanner.
type OSVScanner struct{}

func (o *OSVScanner) Name() string          { return "osv-scanner" }
func (o *OSVScanner) RequiresInternet() bool { return true }

func (o *OSVScanner) Scan(ctx context.Context, projectPath string, _ []string) ([]Finding, error) {
	cmd := exec.CommandContext(ctx, "osv-scanner",
		"scan", "source",
		"-r", projectPath,
		"--format", "json",
	)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// OSV-Scanner returns 1 when vulnerabilities are found
			if exitErr.ExitCode() == 1 && len(out) > 0 {
				// Parse output below
			} else {
				errMsg := strings.TrimSpace(string(exitErr.Stderr))
				if errMsg == "" {
					errMsg = string(out)
				}
				return nil, fmt.Errorf("osv-scanner failed: %s", Truncate(errMsg, 300))
			}
		} else {
			return nil, fmt.Errorf("osv-scanner: %w", err)
		}
	}

	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, nil
	}

	var data osvOutput
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, fmt.Errorf("osv-scanner returned invalid JSON: %w", err)
	}

	return parseOSVResults(data), nil
}

// --- OSV-Scanner JSON structures ---

type osvOutput struct {
	Results []osvResultBlock `json:"results"`
}

type osvResultBlock struct {
	Source   string       `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvPackage struct {
	Package         osvPkgInfo `json:"package"`
	Vulnerabilities []osvVuln  `json:"vulnerabilities"`
}

type osvPkgInfo struct {
	Name string `json:"name"`
}

type osvVuln struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	Details string `json:"details"`
}

func parseOSVResults(data osvOutput) []Finding {
	var findings []Finding

	for _, block := range data.Results {
		for _, pkg := range block.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				title := vuln.Summary
				if title == "" {
					title = vuln.ID
				}
				desc := vuln.Details
				if desc == "" {
					desc = vuln.Summary
				}

				findings = append(findings, Finding{
					Tool:        "osv-scanner",
					Type:        "vulnerability",
					Severity:    SeverityHigh,
					RuleID:      vuln.ID,
					Title:       Truncate(title, 200),
					Description: Truncate(desc, 500),
					Message:     Truncate(fmt.Sprintf("Dependency vulnerability: %s", vuln.ID), 200),
					File:        block.Source,
					Line:        0,
					Package:     pkg.Package.Name,
				})
			}
		}
	}

	return findings
}
