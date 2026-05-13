package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AshishOP/authent8/internal/ignore"
)

// GitleaksScanner wraps the Gitleaks secret detection scanner.
type GitleaksScanner struct{}

func (g *GitleaksScanner) Name() string          { return "gitleaks" }
func (g *GitleaksScanner) RequiresInternet() bool { return false }

func (g *GitleaksScanner) Scan(ctx context.Context, projectPath string, ignorePatterns []string) ([]Finding, error) {
	tmpDir, err := os.MkdirTemp("", "authent8-gitleaks-*")
	if err != nil {
		return nil, fmt.Errorf("gitleaks: failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Build gitleaks config with ignore patterns merged in
	configPath := g.createGitleaksConfig(tmpDir, ignorePatterns)
	reportPath := filepath.Join(tmpDir, "gitleaks_report.json")

	cmd := exec.CommandContext(ctx, "gitleaks", "detect",
		"--source", projectPath,
		"--report-path", reportPath,
		"--report-format", "json",
		"--config", configPath,
		"--no-git",
		"--redact",
	)
	_ = cmd.Run() // gitleaks returns 1 when secrets are found — not an error

	// Read the report file
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		// No report means no findings (exit code 0)
		return nil, nil
	}

	var secrets []gitleaksSecret
	if err := json.Unmarshal(reportData, &secrets); err != nil {
		return nil, fmt.Errorf("gitleaks report JSON invalid: %w", err)
	}

	if len(secrets) == 0 {
		return nil, nil
	}

	// Filter using ignore patterns
	var filtered []gitleaksSecret
	for _, s := range secrets {
		filePath := filepath.Join(projectPath, s.File)
		if !ignore.ShouldIgnore(filePath, projectPath, ignorePatterns) {
			filtered = append(filtered, s)
		}
	}

	return parseGitleaksResults(filtered), nil
}

// createGitleaksConfig generates a temporary TOML config with allowlist patterns.
func (g *GitleaksScanner) createGitleaksConfig(tmpDir string, ignorePatterns []string) string {
	// Start with embedded config as base
	baseConfig, err := EmbeddedConfigs.ReadFile("configs/gitleaks.toml")
	if err != nil {
		// Fallback: generate minimal config
		baseConfig = []byte("[extend]\nuseDefault = true\n")
	}

	// Build additional allowlist paths from ignore patterns
	var extraPaths []string
	extraPaths = append(extraPaths, "\\.env\\.example")
	for _, p := range ignorePatterns {
		clean := strings.ReplaceAll(p, ".", "\\.")
		clean = strings.ReplaceAll(clean, "*", ".*")
		extraPaths = append(extraPaths, clean)
	}

	// Write the config
	configPath := filepath.Join(tmpDir, "gitleaks.toml")
	_ = os.WriteFile(configPath, baseConfig, 0600)

	return configPath
}

// --- Gitleaks JSON structures ---

type gitleaksSecret struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	Match       string `json:"Match"`
}

func parseGitleaksResults(secrets []gitleaksSecret) []Finding {
	var findings []Finding

	for _, s := range secrets {
		desc := s.Description
		if desc == "" {
			desc = fmt.Sprintf("Secret detected: %s", s.RuleID)
		}

		findings = append(findings, Finding{
			Tool:     "gitleaks",
			Type:     "secret",
			Severity: SeverityCritical,
			RuleID:   s.RuleID,
			Title:    desc,
			Description: Truncate(desc, 500),
			Message:  fmt.Sprintf("Hardcoded secret found: %s", s.RuleID),
			File:     s.File,
			Line:     s.StartLine,
		})
	}

	return findings
}
