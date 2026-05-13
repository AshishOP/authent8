// Package installer checks for required scanner tools and warns if missing.
// Security: Never auto-installs binaries. Only checks exec.LookPath.
package installer

import (
	"fmt"
	"os/exec"
	"strings"
)

// ToolInfo describes a scanner tool and how to install it.
type ToolInfo struct {
	Name        string
	Binary      string
	InstallHint string
	Required    bool // If true, scan will skip this tool if missing
}

// RequiredTools lists all scanner tools with install instructions.
var RequiredTools = []ToolInfo{
	{
		Name:        "Trivy",
		Binary:      "trivy",
		InstallHint: "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin",
		Required:    true,
	},
	{
		Name:        "Semgrep",
		Binary:      "semgrep",
		InstallHint: "pipx install semgrep",
		Required:    true,
	},
	{
		Name:        "Gitleaks",
		Binary:      "gitleaks",
		InstallHint: "brew install gitleaks  OR  go install github.com/gitleaks/gitleaks/v8@latest",
		Required:    true,
	},
	{
		Name:        "Bandit",
		Binary:      "bandit",
		InstallHint: "pipx install bandit",
		Required:    false,
	},
	{
		Name:        "detect-secrets",
		Binary:      "detect-secrets",
		InstallHint: "pipx install detect-secrets",
		Required:    false,
	},
	{
		Name:        "Checkov",
		Binary:      "checkov",
		InstallHint: "pipx install checkov",
		Required:    false,
	},
	{
		Name:        "Grype",
		Binary:      "grype",
		InstallHint: "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
		Required:    true,
	},
	{
		Name:        "OSV-Scanner",
		Binary:      "osv-scanner",
		InstallHint: "go install github.com/google/osv-scanner/cmd/osv-scanner@latest",
		Required:    false,
	},
}

// CheckResult reports the status of a single tool.
type CheckResult struct {
	Tool      ToolInfo
	Installed bool
	Path      string
	Version   string
}

// CheckAll verifies all required tools are available on PATH.
// Returns the list of results and a count of missing required tools.
func CheckAll() ([]CheckResult, int) {
	var results []CheckResult
	missingRequired := 0

	for _, tool := range RequiredTools {
		result := CheckResult{Tool: tool}

		path, err := exec.LookPath(tool.Binary)
		if err == nil {
			result.Installed = true
			result.Path = path
			// Try to get version (best effort)
			result.Version = getVersion(tool.Binary)
		} else if tool.Required {
			missingRequired++
		}

		results = append(results, result)
	}

	return results, missingRequired
}

// CheckOne checks if a specific tool is available.
func CheckOne(binary string) bool {
	_, err := exec.LookPath(binary)
	return err == nil
}

// getVersion attempts to extract a version string from a tool.
func getVersion(binary string) string {
	// Try common version flags
	for _, flag := range []string{"--version", "version", "-v"} {
		// Security: Only run the binary with a version flag — no user input
		cmd := exec.Command(binary, flag)
		out, err := cmd.Output()
		if err == nil {
			version := strings.TrimSpace(string(out))
			// Return first line only (some tools are verbose)
			if idx := strings.IndexByte(version, '\n'); idx >= 0 {
				version = version[:idx]
			}
			if len(version) > 0 && len(version) < 200 {
				return version
			}
		}
	}
	return "unknown"
}

// FormatMissing returns a user-friendly message about missing tools.
func FormatMissing(results []CheckResult) string {
	var missing []string
	for _, r := range results {
		if !r.Installed {
			missing = append(missing, fmt.Sprintf("  • %s: %s", r.Tool.Name, r.Tool.InstallHint))
		}
	}
	if len(missing) == 0 {
		return ""
	}
	return "Missing tools:\n" + strings.Join(missing, "\n")
}
