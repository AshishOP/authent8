package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// TrivyScanner wraps the Trivy vulnerability and misconfiguration scanner.
type TrivyScanner struct{}

func (t *TrivyScanner) Name() string          { return "trivy" }
func (t *TrivyScanner) RequiresInternet() bool { return true }

func (t *TrivyScanner) Scan(ctx context.Context, projectPath string, ignorePatterns []string) ([]Finding, error) {
	// Write embedded trivy config to a temp file
	configData, err := EmbeddedConfigs.ReadFile("configs/trivy.yaml")
	if err != nil {
		return nil, fmt.Errorf("trivy: failed to read embedded config: %w", err)
	}
	tmpConfig, err := os.CreateTemp("", "authent8-trivy-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("trivy: failed to create temp config: %w", err)
	}
	defer os.Remove(tmpConfig.Name())
	if _, err := tmpConfig.Write(configData); err != nil {
		tmpConfig.Close()
		return nil, fmt.Errorf("trivy: failed to write temp config: %w", err)
	}
	tmpConfig.Close()

	args := []string{
		"fs",
		"--config", tmpConfig.Name(),
		"--severity", "CRITICAL,HIGH,MEDIUM",
		"--scanners", "vuln,misconfig",
		"--format", "json",
		"--quiet",
	}

	for _, p := range ignorePatterns {
		args = append(args, "--skip-dirs", p)
		args = append(args, "--skip-files", p)
	}
	args = append(args, projectPath)

	cmd := exec.CommandContext(ctx, "trivy", args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			errMsg := strings.TrimSpace(string(exitErr.Stderr))
			if errMsg == "" {
				errMsg = string(out)
			}
			return nil, fmt.Errorf("trivy failed: %s", Truncate(errMsg, 300))
		}
		return nil, fmt.Errorf("trivy: %w", err)
	}

	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, nil
	}

	var data trivyOutput
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, fmt.Errorf("trivy returned invalid JSON: %w", err)
	}

	return parseTrivyResults(data), nil
}

// --- Trivy JSON structures ---

type trivyOutput struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target            string              `json:"Target"`
	Vulnerabilities   []trivyVuln         `json:"Vulnerabilities"`
	Misconfigurations []trivyMisconfig    `json:"Misconfigurations"`
}

type trivyVuln struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgName         string `json:"PkgName"`
	Severity        string `json:"Severity"`
	Title           string `json:"Title"`
	Description     string `json:"Description"`
	FixedVersion    string `json:"FixedVersion"`
}

type trivyMisconfig struct {
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Message     string `json:"Message"`
	Severity    string `json:"Severity"`
}

func parseTrivyResults(data trivyOutput) []Finding {
	var findings []Finding

	for _, result := range data.Results {
		target := result.Target
		if target == "" {
			target = "dependencies"
		}

		for _, vuln := range result.Vulnerabilities {
			findings = append(findings, Finding{
				Tool:        "trivy",
				Type:        "vulnerability",
				Severity:    NormalizeSeverity(vuln.Severity),
				RuleID:      vuln.VulnerabilityID,
				Title:       Truncate(vuln.Title, 200),
				Description: Truncate(vuln.Description, 500),
				Message:     Truncate(vuln.Title, 200),
				File:        target,
				Line:        0,
				Package:     vuln.PkgName,
				FixedVersion: vuln.FixedVersion,
			})
		}

		for _, mc := range result.Misconfigurations {
			msg := mc.Message
			if msg == "" {
				msg = mc.Title
			}
			fileTarget := target
			if fileTarget == "" {
				fileTarget = "infrastructure"
			}
			findings = append(findings, Finding{
				Tool:        "trivy",
				Type:        "misconfig",
				Severity:    NormalizeSeverity(mc.Severity),
				RuleID:      mc.ID,
				Title:       Truncate(mc.Title, 200),
				Description: Truncate(mc.Description, 500),
				Message:     Truncate(msg, 200),
				File:        fileTarget,
				Line:        0,
			})
		}
	}

	return findings
}

// writeEmbeddedConfig writes an embedded config file to a temp directory and returns its path.
// The caller is responsible for cleaning up the parent directory.
func writeEmbeddedConfig(name, tmpDir string) (string, error) {
	data, err := EmbeddedConfigs.ReadFile("configs/" + filepath.Base(name))
	if err != nil {
		return "", fmt.Errorf("failed to read embedded %s: %w", name, err)
	}
	outPath := filepath.Join(tmpDir, filepath.Base(name))
	if err := os.WriteFile(outPath, data, 0600); err != nil {
		return "", fmt.Errorf("failed to write temp %s: %w", name, err)
	}
	return outPath, nil
}
