// Package ui provides terminal styling and themed output for the Authent8 CLI.
package ui

import "github.com/charmbracelet/lipgloss"

// Theme colors — dark professional palette.
var (
	ColorPrimary   = lipgloss.Color("#7C3AED") // Purple
	ColorSecondary = lipgloss.Color("#06B6D4") // Cyan
	ColorSuccess   = lipgloss.Color("#22C55E") // Green
	ColorWarning   = lipgloss.Color("#F59E0B") // Amber
	ColorError     = lipgloss.Color("#EF4444") // Red
	ColorCritical  = lipgloss.Color("#DC2626") // Dark Red
	ColorMuted     = lipgloss.Color("#6B7280") // Gray
	ColorWhite     = lipgloss.Color("#F9FAFB") // Off-white
	ColorDim       = lipgloss.Color("#9CA3AF") // Light gray
)

// Styled text helpers.
var (
	Bold     = lipgloss.NewStyle().Bold(true)
	Dim      = lipgloss.NewStyle().Foreground(ColorDim)
	Muted    = lipgloss.NewStyle().Foreground(ColorMuted)
	Success  = lipgloss.NewStyle().Foreground(ColorSuccess)
	Warning  = lipgloss.NewStyle().Foreground(ColorWarning)
	Error    = lipgloss.NewStyle().Foreground(ColorError)
	Critical = lipgloss.NewStyle().Foreground(ColorCritical).Bold(true)
	Primary  = lipgloss.NewStyle().Foreground(ColorPrimary)
	Info     = lipgloss.NewStyle().Foreground(ColorSecondary)
)

// SeverityStyle returns the appropriate style for a severity level.
func SeverityStyle(severity string) lipgloss.Style {
	switch severity {
	case "CRITICAL":
		return Critical
	case "HIGH":
		return Error
	case "MEDIUM":
		return Warning
	case "LOW":
		return Info
	default:
		return Muted
	}
}

// SeverityIcon returns an emoji for a severity level.
func SeverityIcon(severity string) string {
	switch severity {
	case "CRITICAL":
		return "🔴"
	case "HIGH":
		return "🟠"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🟢"
	default:
		return "⚪"
	}
}

// ToolIcon returns an icon for a scanner tool.
func ToolIcon(tool string) string {
	switch tool {
	case "trivy":
		return "🛡️"
	case "semgrep":
		return "🔍"
	case "gitleaks":
		return "🔑"
	case "bandit":
		return "🐍"
	case "detect-secrets":
		return "🕵️"
	case "checkov":
		return "📋"
	case "grype":
		return "🦠"
	case "osv-scanner":
		return "📦"
	default:
		return "🔧"
	}
}

// StatusStyle helpers for scan progress.
var (
	StatusRunning  = lipgloss.NewStyle().Foreground(ColorSecondary)
	StatusDone     = lipgloss.NewStyle().Foreground(ColorSuccess)
	StatusFailed   = lipgloss.NewStyle().Foreground(ColorError)
	StatusSkipped  = lipgloss.NewStyle().Foreground(ColorMuted)
)

// Box creates a bordered box with a title.
func Box(title, content string) string {
	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorPrimary).
		Padding(0, 1).
		Width(70)

	titleStyle := lipgloss.NewStyle().
		Foreground(ColorPrimary).
		Bold(true)

	return titleStyle.Render(title) + "\n" + style.Render(content)
}
