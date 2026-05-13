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

// GrypeScanner wraps the Grype vulnerability scanner.
type GrypeScanner struct{}

func (g *GrypeScanner) Name() string          { return "grype" }
func (g *GrypeScanner) RequiresInternet() bool { return true }

func (g *GrypeScanner) Scan(ctx context.Context, projectPath string, ignorePatterns []string) ([]Finding, error) {
	args := []string{
		fmt.Sprintf("dir:%s", projectPath),
		"-o", "json",
		"--quiet",
	}
	// Exclude environment directories
	for _, rel := range []string{".venv", "venv", "site-packages", ".git", "__pycache__"} {
		args = append(args, "--exclude", filepath.Join(projectPath, rel))
	}

	cmd := exec.CommandContext(ctx, "grype", args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Grype returns 1 or 2 when vulnerabilities are found
			if (exitErr.ExitCode() == 1 || exitErr.ExitCode() == 2) && len(out) > 0 {
				// Parse output below
			} else {
				errMsg := strings.TrimSpace(string(exitErr.Stderr))
				if errMsg == "" {
					errMsg = string(out)
				}
				return nil, fmt.Errorf("grype failed: %s", Truncate(errMsg, 300))
			}
		} else {
			return nil, fmt.Errorf("grype: %w", err)
		}
	}

	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, nil
	}

	var data grypeOutput
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, fmt.Errorf("grype returned invalid JSON: %w", err)
	}

	return parseGrypeResults(data, projectPath, ignorePatterns), nil
}

// --- Grype JSON structures ---

type grypeOutput struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability grypeVuln     `json:"vulnerability"`
	Artifact      grypeArtifact `json:"artifact"`
}

type grypeVuln struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Fix         *grypeFix `json:"fix"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
}

type grypeArtifact struct {
	Name      string           `json:"name"`
	Locations []grypeLocation  `json:"locations"`
}

type grypeLocation struct {
	Path string `json:"path"`
}

func parseGrypeResults(data grypeOutput, projectPath string, ignorePatterns []string) []Finding {
	var findings []Finding

	for _, match := range data.Matches {
		location := "dependencies"
		if len(match.Artifact.Locations) > 0 {
			location = match.Artifact.Locations[0].Path
		}

		// Skip non-repo metadata noise (e.g., METADATA from environment packages)
		baseName := filepath.Base(location)
		if baseName == "METADATA" || baseName == "PKG-INFO" {
			fullPath := filepath.Join(projectPath, location)
			if _, err := filepath.Abs(fullPath); err != nil {
				continue
			}
		}

		// Apply ignore patterns
		if len(ignorePatterns) > 0 {
			locationPath := filepath.Join(projectPath, location)
			if ignore.ShouldIgnore(locationPath, projectPath, ignorePatterns) {
				continue
			}
		}

		fixedVersion := ""
		if match.Vulnerability.Fix != nil && len(match.Vulnerability.Fix.Versions) > 0 {
			fixedVersion = match.Vulnerability.Fix.Versions[0]
		}

		findings = append(findings, Finding{
			Tool:         "grype",
			Type:         "vulnerability",
			Severity:     NormalizeSeverity(match.Vulnerability.Severity),
			RuleID:       match.Vulnerability.ID,
			Title:        Truncate(match.Vulnerability.ID, 200),
			Description:  Truncate(match.Vulnerability.Description, 500),
			Message:      Truncate(fmt.Sprintf("%s vulnerable: %s", match.Artifact.Name, match.Vulnerability.ID), 200),
			File:         location,
			Line:         0,
			Package:      match.Artifact.Name,
			FixedVersion: fixedVersion,
		})
	}

	return findings
}
