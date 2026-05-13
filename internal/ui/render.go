package ui

import "fmt"

// Banner prints the Authent8 ASCII art banner.
func Banner(version string) string {
	banner := `
   ___         __  __              __  ___
  / _ | __ __ / /_/ /  ___  ___  / /_( _ )
 / __ |/ // // __/ _ \/ -_)/ _ \/ __/ _  |
/_/ |_|\_,_/ \__/_//_/\__//_//_/\__/\___/
`
	return Primary.Render(banner) + "\n" +
		Dim.Render(fmt.Sprintf("  v%s — Privacy-First Security Scanner", version)) + "\n" +
		Muted.Render("  https://github.com/AshishOP/authent8") + "\n"
}

// ScanHeader prints the header for a scan operation.
func ScanHeader(path string) string {
	return "\n" +
		Bold.Render("🔍 Scanning: ") +
		Info.Render(path) + "\n"
}

// ScanComplete prints the completion message.
func ScanComplete(duration float64) string {
	return "\n" +
		Success.Render(fmt.Sprintf("✅ Scan complete in %.1fs", duration)) + "\n"
}

// PrintToolStatus formats a scanner's completion status.
func PrintToolStatus(tool string, findingCount int, err error) string {
	icon := ToolIcon(tool)
	if err != nil {
		return fmt.Sprintf("  %s %-15s %s", icon, tool, StatusFailed.Render("✗ "+err.Error()))
	}
	if findingCount == 0 {
		return fmt.Sprintf("  %s %-15s %s", icon, tool, StatusDone.Render("✓ clean"))
	}
	return fmt.Sprintf("  %s %-15s %s",
		icon, tool,
		Warning.Render(fmt.Sprintf("⚠ %d findings", findingCount)))
}

// PrintSummary formats the scan summary.
func PrintSummary(total, critical, high, medium, low, suppressed int) string {
	s := "\n" + Box("📊 Scan Summary", fmt.Sprintf(
		"Total Findings:   %d\n"+
			"Suppressed (FP):  %d\n"+
			"\n"+
			"  %s Critical: %d\n"+
			"  %s High:     %d\n"+
			"  %s Medium:   %d\n"+
			"  %s Low:      %d",
		total, suppressed,
		SeverityIcon("CRITICAL"), critical,
		SeverityIcon("HIGH"), high,
		SeverityIcon("MEDIUM"), medium,
		SeverityIcon("LOW"), low,
	))
	return s
}

// PrintFinding formats a single finding for display.
func PrintFinding(index int, tool, severity, ruleID, file string, line int, message, fixSuggestion string, isFP bool, confidence int) string {
	sevStyle := SeverityStyle(severity)
	icon := SeverityIcon(severity)

	header := fmt.Sprintf("  %s %s %s",
		icon,
		sevStyle.Render(fmt.Sprintf("[%s]", severity)),
		Bold.Render(ruleID))

	location := Dim.Render(fmt.Sprintf("     %s:%d", file, line))
	msg := fmt.Sprintf("     %s", message)

	result := header + "\n" + location + "\n" + msg

	if isFP {
		result += "\n" + Muted.Render(fmt.Sprintf("     → FALSE POSITIVE (confidence: %d%%)", confidence))
	} else if fixSuggestion != "" {
		result += "\n" + Success.Render(fmt.Sprintf("     💡 Fix: %s", fixSuggestion))
	}

	return result + "\n"
}

// PrivacyReport renders the post-scan privacy transparency report.
func PrivacyReport(findingCount int, scanID string) string {
	return Box("🔒 Privacy Report", fmt.Sprintf(
		"✅ Source Code:    Scanned locally, never stored\n"+
			"✅ Database:       %d findings metadata only\n"+
			"✅ Code Snippets:  Max 5 lines, secrets redacted\n"+
			"✅ AI Training:    NEVER\n"+
			"✅ Data Retention: 30 days (delete anytime)\n"+
			"\n"+
			"Scan ID: %s",
		findingCount, scanID))
}
