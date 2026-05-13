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
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	stdoutStr := strings.TrimSpace(stdout.String())

	// OSV-Scanner returns exit code 1 when vulnerabilities are found — try parse first
	if stdoutStr != "" {
		var data osvOutput
		if jsonErr := json.Unmarshal([]byte(stdoutStr), &data); jsonErr == nil {
			return parseOSVResults(data), nil
		}
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 1 = vulnerabilities found but we couldn't parse — report that
			if exitErr.ExitCode() == 1 {
				return nil, fmt.Errorf("osv-scanner found vulnerabilities but output parsing failed")
			}
		}
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return nil, fmt.Errorf("osv-scanner failed: %s", Truncate(errMsg, 300))
	}

	return nil, nil
}

// --- OSV-Scanner JSON structures ---
// OSV-Scanner v2 changed source from a string to an object.

type osvOutput struct {
	Results []osvResultBlock `json:"results"`
}

type osvResultBlock struct {
	Source   osvSource    `json:"source"`
	Packages []osvPackage `json:"packages"`
}

// osvSource handles both v1 (string) and v2 (object) formats.
type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

// UnmarshalJSON handles source being either a string or an object.
func (s *osvSource) UnmarshalJSON(data []byte) error {
	// Try as string first (v1)
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		s.Path = str
		s.Type = "unknown"
		return nil
	}

	// Try as object (v2)
	type osvSourceRaw struct {
		Path string `json:"path"`
		Type string `json:"type"`
	}
	var obj osvSourceRaw
	if err := json.Unmarshal(data, &obj); err == nil {
		s.Path = obj.Path
		s.Type = obj.Type
		return nil
	}

	return fmt.Errorf("cannot unmarshal osv source: %s", string(data))
}

type osvPackage struct {
	Package         osvPkgInfo `json:"package"`
	Vulnerabilities []osvVuln  `json:"vulnerabilities"`
	Groups          []osvGroup `json:"groups"`
}

type osvPkgInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvVuln struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	Details string `json:"details"`
}

type osvGroup struct {
	IDs     []string `json:"ids"`
	Aliases []string `json:"aliases"`
}

func parseOSVResults(data osvOutput) []Finding {
	var findings []Finding

	for _, block := range data.Results {
		for _, pkg := range block.Packages {
			// Get vulnerabilities from either direct vulns or groups
			if len(pkg.Vulnerabilities) > 0 {
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
						File:        block.Source.Path,
						Line:        0,
						Package:     pkg.Package.Name,
					})
				}
			} else if len(pkg.Groups) > 0 {
				// OSV-Scanner v2 uses groups instead of inline vulnerabilities
				for _, group := range pkg.Groups {
					for _, id := range group.IDs {
						findings = append(findings, Finding{
							Tool:        "osv-scanner",
							Type:        "vulnerability",
							Severity:    SeverityHigh,
							RuleID:      id,
							Title:       Truncate(fmt.Sprintf("%s: %s %s", id, pkg.Package.Name, pkg.Package.Version), 200),
							Description: fmt.Sprintf("Vulnerability %s in %s %s (%s)", id, pkg.Package.Name, pkg.Package.Version, pkg.Package.Ecosystem),
							Message:     Truncate(fmt.Sprintf("Dependency vulnerability: %s", id), 200),
							File:        block.Source.Path,
							Line:        0,
							Package:     pkg.Package.Name,
						})
					}
				}
			}
		}
	}

	return findings
}
