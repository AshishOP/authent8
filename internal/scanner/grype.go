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
		args = append(args, "--exclude", filepath.Join("**", rel))
	}

	cmd := exec.CommandContext(ctx, "grype", args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	stdoutStr := strings.TrimSpace(stdout.String())

	// Grype returns exit code 1 when vulns found — always try parsing stdout first
	if stdoutStr != "" {
		var data grypeOutput
		if jsonErr := json.Unmarshal([]byte(stdoutStr), &data); jsonErr == nil {
			return parseGrypeResults(data, projectPath, ignorePatterns), nil
		}
	}

	if err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = "unknown error (no stderr output)"
		}
		return nil, fmt.Errorf("grype failed: %s", Truncate(errMsg, 300))
	}

	return nil, nil
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
	ID          string    `json:"id"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Fix         *grypeFix `json:"fix"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type grypeArtifact struct {
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	Locations []grypeLocation `json:"locations"`
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
			continue
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
			Message:      Truncate(fmt.Sprintf("%s %s vulnerable: %s", match.Artifact.Name, match.Artifact.Version, match.Vulnerability.ID), 200),
			File:         location,
			Line:         0,
			Package:      match.Artifact.Name,
			FixedVersion: fixedVersion,
		})
	}

	return findings
}
