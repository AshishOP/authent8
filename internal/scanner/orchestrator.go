package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AshishOP/authent8/internal/fp"
	"github.com/AshishOP/authent8/internal/ignore"
)

// AllTools lists every scanner tool name in execution order.
var AllTools = []string{
	"trivy", "semgrep", "gitleaks", "bandit",
	"detect-secrets", "checkov", "grype", "osv-scanner",
}

// OnlineRequiredTools lists scanners that need internet access.
var OnlineRequiredTools = map[string]bool{
	"trivy": true, "semgrep": true, "grype": true, "osv-scanner": true,
}

// Orchestrator runs all scanners in parallel and normalizes results.
type Orchestrator struct {
	ProjectPath    string
	Results        map[string][]Finding
	Errors         map[string]string
	ScanDuration   time.Duration
	FPManager      *fp.Manager
	IgnorePatterns []string

	scanners map[string]Scanner
	mu       sync.Mutex
}

// NewOrchestrator creates an Orchestrator for the given project directory.
func NewOrchestrator(projectPath string) (*Orchestrator, error) {
	abs, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, fmt.Errorf("invalid project path: %w", err)
	}
	if _, err := os.Stat(abs); os.IsNotExist(err) {
		return nil, fmt.Errorf("project path does not exist: %s", projectPath)
	}

	o := &Orchestrator{
		ProjectPath: abs,
		Results:     make(map[string][]Finding),
		Errors:      make(map[string]string),
		FPManager:   fp.New(abs),
		IgnorePatterns: ignore.LoadPatterns(abs),
		scanners: map[string]Scanner{
			"trivy":          &TrivyScanner{},
			"semgrep":        &SemgrepScanner{},
			"gitleaks":       &GitleaksScanner{},
			"bandit":         &BanditScanner{},
			"detect-secrets": &DetectSecretsScanner{},
			"checkov":        &CheckovScanner{},
			"grype":          &GrypeScanner{},
			"osv-scanner":    &OSVScanner{},
		},
	}

	// Initialize results map
	for _, tool := range AllTools {
		o.Results[tool] = nil
	}

	return o, nil
}

// GetScanPlan returns the list of tools to run based on connectivity.
func (o *Orchestrator) GetScanPlan(online bool) []string {
	if online {
		return AllTools
	}
	var offline []string
	for _, t := range AllTools {
		if !OnlineRequiredTools[t] {
			offline = append(offline, t)
		}
	}
	return offline
}

// ScanTool runs a single scanner by name.
func (o *Orchestrator) ScanTool(ctx context.Context, toolName string) ([]Finding, error) {
	s, ok := o.scanners[toolName]
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", toolName)
	}
	return s.Scan(ctx, o.ProjectPath, o.IgnorePatterns)
}

// ScanAllParallel runs all scanners concurrently using goroutines.
// onResult is called as each scanner completes (thread-safe).
func (o *Orchestrator) ScanAllParallel(ctx context.Context, tools []string, onResult func(tool string, findings []Finding, err error)) {
	start := time.Now()
	var wg sync.WaitGroup

	for _, toolName := range tools {
		s, ok := o.scanners[toolName]
		if !ok {
			continue
		}
		wg.Add(1)
		go func(name string, scanner Scanner) {
			defer wg.Done()

			// Per-scanner timeout: 10 minutes
			scanCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			defer cancel()

			findings, err := scanner.Scan(scanCtx, o.ProjectPath, o.IgnorePatterns)

			o.mu.Lock()
			if err != nil {
				o.Errors[name] = err.Error()
				o.Results[name] = nil
			} else {
				o.Results[name] = findings
			}
			o.mu.Unlock()

			if onResult != nil {
				onResult(name, findings, err)
			}
		}(toolName, s)
	}

	wg.Wait()
	o.ScanDuration = time.Since(start)
}

// GetAllFindings returns a flattened list of all findings, optionally including ignored ones.
func (o *Orchestrator) GetAllFindings(includeIgnored bool) []Finding {
	var all []Finding
	for _, findings := range o.Results {
		all = append(all, findings...)
	}

	// Enrich code snippets where missing
	o.enrichCodeSnippets(all)

	if !includeIgnored {
		var filtered []Finding
		for i := range all {
			if !o.FPManager.IsIgnored(&all[i]) {
				filtered = append(filtered, all[i])
			}
		}
		return filtered
	}

	return all
}

// GetSummary returns aggregate scan statistics.
func (o *Orchestrator) GetSummary() ScanSummary {
	active := o.GetAllFindings(false)
	totalRaw := 0
	for _, findings := range o.Results {
		totalRaw += len(findings)
	}

	byTool := make(map[string]int)
	bySeverity := map[string]int{
		"critical": 0, "high": 0, "medium": 0, "low": 0,
	}

	for _, f := range active {
		byTool[f.Tool]++
		switch f.Severity {
		case SeverityCritical:
			bySeverity["critical"]++
		case SeverityHigh:
			bySeverity["high"]++
		case SeverityMedium:
			bySeverity["medium"]++
		case SeverityLow:
			bySeverity["low"]++
		}
	}

	return ScanSummary{
		TotalFindings:   len(active),
		Suppressed:      totalRaw - len(active),
		ByTool:          byTool,
		BySeverity:      bySeverity,
		DurationSeconds: o.ScanDuration.Seconds(),
		Errors:          o.Errors,
	}
}

// enrichCodeSnippets reads actual source lines for findings missing a snippet.
func (o *Orchestrator) enrichCodeSnippets(findings []Finding) {
	for i := range findings {
		f := &findings[i]
		snippet := f.CodeSnippet
		if snippet != "" && len(snippet) >= 3 {
			continue
		}

		filePath := f.File
		if filePath == "" {
			continue
		}

		// Resolve relative to project path
		fullPath := filepath.Join(o.ProjectPath, filePath)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			fullPath = filePath // Maybe it's already absolute
		}

		info, err := os.Stat(fullPath)
		if err != nil || info.IsDir() {
			continue
		}

		file, err := os.Open(fullPath)
		if err != nil {
			continue
		}

		lineNum := f.Line
		if lineNum <= 0 {
			file.Close()
			continue
		}

		scanner := bufio.NewScanner(file)
		current := 0
		for scanner.Scan() {
			current++
			if current == lineNum {
				f.CodeSnippet = strings.TrimSpace(scanner.Text())
				break
			}
		}
		file.Close()
	}
}
