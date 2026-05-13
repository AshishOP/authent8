// Package scanner provides embedded configuration files for security tools.
package scanner

import "embed"

// EmbeddedConfigs holds all scanner configuration files embedded at compile time.
//
//go:embed configs/*
var EmbeddedConfigs embed.FS
