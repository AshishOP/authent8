// Authent8 v3.0.0 — Privacy-First Security Scanner
// Rewritten in Go for maximum performance and efficiency.
//
// Security hardening:
// - No shell=true anywhere — all exec.Command calls use argument arrays
// - API keys never logged or printed
// - Temp files created with restrictive permissions (0600)
// - Response body size limited to prevent memory exhaustion
// - User input validated before use
// - No arbitrary code execution
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/AshishOP/authent8/internal/ai"
	"github.com/AshishOP/authent8/internal/config"
	"github.com/AshishOP/authent8/internal/history"
	"github.com/AshishOP/authent8/internal/installer"
	netutil "github.com/AshishOP/authent8/internal/net"
	"github.com/AshishOP/authent8/internal/scanner"
	"github.com/AshishOP/authent8/internal/types"
	"github.com/AshishOP/authent8/internal/ui"
)

var version = "3.0.0"

func main() {
	// Load config from .authent8.env
	config.Load()

	rootCmd := &cobra.Command{
		Use:   "authent8",
		Short: "Authent8 — Privacy-First Security Scanner",
		Long:  "A DevSecOps tool that scans your code for vulnerabilities, secrets, and misconfigurations using 8 industry-standard scanners with AI-powered false positive detection.",
	}

	rootCmd.AddCommand(
		scanCmd(),
		checkCmd(),
		historyCmd(),
		versionCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// --- scan command ---

func scanCmd() *cobra.Command {
	var (
		path     string
		noAI     bool
		offline  bool
		jsonOut  bool
		tools    []string
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Run security scan on a project",
		Long:  "Scans the target directory with up to 8 security scanners in parallel, then validates findings using heuristics and AI.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Resolve scan path
			if len(args) > 0 {
				path = args[0]
			}
			if path == "" {
				path = "."
			}

			absPath, err := filepath.Abs(path)
			if err != nil {
				return fmt.Errorf("invalid path: %w", err)
			}

			// Security: Validate the path exists and is a directory
			info, err := os.Stat(absPath)
			if err != nil {
				return fmt.Errorf("path does not exist: %s", absPath)
			}
			if !info.IsDir() {
				return fmt.Errorf("path is not a directory: %s", absPath)
			}

			if !jsonOut {
				fmt.Print(ui.Banner(version))
				fmt.Print(ui.ScanHeader(absPath))
			}

			// Check connectivity
			online := !offline
			if online {
				online = netutil.HasInternet(0)
				if !online && !jsonOut {
					fmt.Println(ui.Warning.Render("  ⚠ No internet — running offline scanners only"))
				}
			}

			// Create orchestrator
			orch, err := scanner.NewOrchestrator(absPath)
			if err != nil {
				return err
			}

			// Determine scan plan
			var scanTools []string
			if len(tools) > 0 {
				scanTools = tools
			} else {
				scanTools = orch.GetScanPlan(online)
			}

			if !jsonOut {
				fmt.Printf("\n  Running %d scanners...\n\n", len(scanTools))
			}

			// Setup graceful shutdown
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigCh
				if !jsonOut {
					fmt.Println("\n\n" + ui.Warning.Render("  ⚠ Scan interrupted — cleaning up..."))
				}
				cancel()
			}()

			// Run all scanners in parallel
			orch.ScanAllParallel(ctx, scanTools, func(tool string, findings []types.Finding, err error) {
				if !jsonOut {
					fmt.Println(ui.PrintToolStatus(tool, len(findings), err))
				}
			})

			// Get results
			allFindings := orch.GetAllFindings(false)

			// AI Validation
			if !noAI {
				aiCfg := config.GetAIConfig()
				validator := ai.New(aiCfg)
				if validator.HasAPIKey() {
					if !jsonOut {
						fmt.Println("\n  🤖 Running AI validation...")
					}
					validator.ValidateFindings(allFindings)
					if !jsonOut {
						// Count false positives detected
						fpCount := 0
						for _, f := range allFindings {
							if f.IsFalsePositive {
								fpCount++
							}
						}
						if fpCount > 0 {
							fmt.Println(ui.Success.Render(fmt.Sprintf("     ✓ %d false positives identified", fpCount)))
						}
					}
				} else if !jsonOut {
					fmt.Println(ui.Muted.Render("\n  ℹ No AI key configured — showing unvalidated results"))
				}
			}

			summary := orch.GetSummary()

			if jsonOut {
				// JSON output mode
				return printJSON(allFindings, summary)
			}

			// Print results
			fmt.Print(ui.ScanComplete(summary.DurationSeconds))

			// Print findings
			if len(allFindings) > 0 {
				fmt.Println("\n" + ui.Bold.Render("📋 Findings:") + "\n")
				for i, f := range allFindings {
					if f.IsFalsePositive {
						continue // Skip false positives in default view
					}
					fmt.Print(ui.PrintFinding(
						i+1, f.Tool, f.Severity, f.RuleID,
						f.File, f.Line, f.Message,
						f.FixSuggestion, f.IsFalsePositive, f.AIConfidence,
					))
				}
			}

			// Summary
			fmt.Print(ui.PrintSummary(
				summary.TotalFindings,
				summary.BySeverity["critical"],
				summary.BySeverity["high"],
				summary.BySeverity["medium"],
				summary.BySeverity["low"],
				summary.Suppressed,
			))

			// Privacy report
			scanID := uuid.New().String()
			fmt.Println()
			fmt.Println(ui.PrivacyReport(len(allFindings), scanID))

			// Scan errors
			if len(summary.Errors) > 0 {
				fmt.Println("\n" + ui.Warning.Render("⚠ Scanner Errors:"))
				for tool, errMsg := range summary.Errors {
					fmt.Printf("  • %s: %s\n", tool, types.Truncate(errMsg, 100))
				}
			}

			// Save to history
			history.Add(absPath, summary.TotalFindings,
				summary.BySeverity["critical"],
				summary.BySeverity["high"],
				summary.DurationSeconds)

			return nil
		},
	}

	cmd.Flags().StringVarP(&path, "path", "p", "", "Project path to scan (default: current directory)")
	cmd.Flags().BoolVar(&noAI, "no-ai", false, "Skip AI validation")
	cmd.Flags().BoolVar(&offline, "offline", false, "Force offline mode (skip online-only scanners)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output results as JSON")
	cmd.Flags().StringSliceVar(&tools, "tools", nil, "Specific tools to run (comma-separated)")

	return cmd
}

// --- check command ---

func checkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Check if required scanner tools are installed",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.Banner(version))
			fmt.Println(ui.Bold.Render("🔧 Tool Status:") + "\n")

			results, missing := installer.CheckAll()

			for _, r := range results {
				icon := ui.ToolIcon(r.Tool.Binary)
				if r.Installed {
					fmt.Printf("  %s %-15s %s  %s\n",
						icon, r.Tool.Name,
						ui.Success.Render("✓ installed"),
						ui.Dim.Render(r.Version))
				} else {
					label := "optional"
					if r.Tool.Required {
						label = "REQUIRED"
					}
					fmt.Printf("  %s %-15s %s  %s\n",
						icon, r.Tool.Name,
						ui.Error.Render("✗ missing"),
						ui.Muted.Render("("+label+")"))
				}
			}

			if missing > 0 {
				fmt.Println("\n" + ui.Warning.Render(fmt.Sprintf("  ⚠ %d required tool(s) missing", missing)))
				fmt.Println("\n" + installer.FormatMissing(results))
			} else {
				fmt.Println("\n" + ui.Success.Render("  ✅ All required tools installed!"))
			}

			// Check internet
			fmt.Print("\n  🌐 Internet: ")
			if netutil.HasInternet(0) {
				fmt.Println(ui.Success.Render("✓ connected"))
			} else {
				fmt.Println(ui.Warning.Render("✗ offline"))
			}

			// Check AI
			fmt.Print("  🤖 AI Key:   ")
			aiCfg := config.GetAIConfig()
			if aiCfg.APIKey != "" {
				fmt.Println(ui.Success.Render("✓ set") + "  " + ui.Dim.Render(aiCfg.Model))
			} else {
				fmt.Println(ui.Muted.Render("✗ not set"))
			}

			return nil
		},
	}
}

// --- history command ---

func historyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "history",
		Short: "Show recent scan history",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.Banner(version))

			entries := history.Recent(10)
			if len(entries) == 0 {
				fmt.Println(ui.Muted.Render("  No scan history yet. Run 'authent8 scan' to start."))
				return nil
			}

			fmt.Println(ui.Bold.Render("📜 Recent Scans:") + "\n")
			for i, e := range entries {
				t, _ := time.Parse(time.RFC3339, e.Timestamp)
				timeStr := t.Format("Jan 02, 15:04")

				severityInfo := ""
				if e.Critical > 0 {
					severityInfo += ui.Critical.Render(fmt.Sprintf(" %d critical", e.Critical))
				}
				if e.High > 0 {
					severityInfo += ui.Error.Render(fmt.Sprintf(" %d high", e.High))
				}

				fmt.Printf("  %d. %s  %s  %s findings%s  (%.1fs)\n",
					i+1,
					ui.Dim.Render(timeStr),
					ui.Info.Render(truncatePath(e.Path, 30)),
					ui.Warning.Render(fmt.Sprintf("%d", e.Findings)),
					severityInfo,
					e.Duration)
			}

			return nil
		},
	}
}

// --- version command ---

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("authent8 v%s\n", version)
			fmt.Println("Built with Go — Privacy-First Security Scanner")
			fmt.Println("https://github.com/AshishOP/authent8")
		},
	}
}

// --- Helpers ---

func printJSON(findings []types.Finding, summary types.ScanSummary) error {
	// Filter out false positives for clean JSON output
	var real []types.Finding
	for _, f := range findings {
		if !f.IsFalsePositive {
			real = append(real, f)
		}
	}

	output := map[string]interface{}{
		"version":  version,
		"summary":  summary,
		"findings": real,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func truncatePath(p string, maxLen int) string {
	if len(p) <= maxLen {
		return p
	}
	// Show last N characters with leading ...
	return "..." + p[len(p)-maxLen+3:]
}


