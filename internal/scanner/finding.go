// Package scanner provides security scanner wrappers for Authent8.
//
// All shared types (Finding, Scanner, ScanSummary) live in the types package
// to prevent import cycles. This file re-exports them for convenience.
package scanner

import "github.com/AshishOP/authent8/internal/types"

// Type aliases — all scanner files use these directly.
type Finding = types.Finding
type ScanSummary = types.ScanSummary

// Re-export constants and helpers.
var (
	SeverityCritical  = types.SeverityCritical
	SeverityHigh      = types.SeverityHigh
	SeverityMedium    = types.SeverityMedium
	SeverityLow       = types.SeverityLow
	NormalizeSeverity = types.NormalizeSeverity
	Truncate          = types.Truncate
)

// Scanner re-exports the Scanner interface from types.
type Scanner = types.Scanner
