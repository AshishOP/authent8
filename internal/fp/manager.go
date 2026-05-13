// Package fp manages false positive suppression via .authent8_fp.json.
// Uses the same SHA-256 hashing scheme as the Python version for backward compatibility.
package fp

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AshishOP/authent8/internal/types"
)

// Manager handles the persistence and lookup of suppressed findings.
type Manager struct {
	projectPath     string
	fpFile          string
	ignoredHashes   map[string]bool
	IgnoredFindings []StoredFinding `json:"findings"`
}

// StoredFinding is the minimal metadata stored for each suppressed finding.
type StoredFinding struct {
	Hash     string `json:"fp_hash"`
	RuleID   string `json:"rule_id,omitempty"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Severity string `json:"severity,omitempty"`
	Code     string `json:"code,omitempty"`
}

type fpData struct {
	Hashes   []string        `json:"hashes"`
	Findings []StoredFinding `json:"findings"`
}

// New creates a Manager for the given project directory.
func New(projectPath string) *Manager {
	m := &Manager{
		projectPath:   projectPath,
		fpFile:        filepath.Join(projectPath, ".authent8_fp.json"),
		ignoredHashes: make(map[string]bool),
	}
	m.load()
	return m
}

// ComputeHash generates a stable SHA-256 hash for a finding.
// Must match the Python implementation for backward compatibility:
//
//	raw = f"{rule_id}|{file}|{normalized_code_or_line}"
//	sha256(raw.encode("utf-8")).hexdigest()
func ComputeHash(f *types.Finding) string {
	rule := f.RuleID
	if rule == "" {
		rule = "unknown"
	}
	file := f.File
	if file == "" {
		file = "unknown"
	}

	code := f.CodeSnippet
	var signature string
	if code != "" {
		// Normalize: remove all whitespace (same as Python's "".join(code.split()))
		signature = strings.Join(strings.Fields(code), "")
	} else {
		signature = fmt.Sprintf("%d", f.Line)
	}

	raw := fmt.Sprintf("%s|%s|%s", rule, file, signature)
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", hash)
}

// IsIgnored returns true if the finding has been suppressed.
func (m *Manager) IsIgnored(f *types.Finding) bool {
	return m.ignoredHashes[ComputeHash(f)]
}

// Add marks a finding as a false positive and persists it.
func (m *Manager) Add(f *types.Finding) {
	h := ComputeHash(f)
	if m.ignoredHashes[h] {
		return
	}
	m.ignoredHashes[h] = true
	m.IgnoredFindings = append(m.IgnoredFindings, StoredFinding{
		Hash:     h,
		RuleID:   f.RuleID,
		File:     f.File,
		Line:     f.Line,
		Severity: f.Severity,
		Code:     f.CodeSnippet,
	})
	m.save()
}

// Remove restores a previously suppressed finding by hash.
func (m *Manager) Remove(hash string) {
	if !m.ignoredHashes[hash] {
		return
	}
	delete(m.ignoredHashes, hash)
	filtered := m.IgnoredFindings[:0]
	for _, sf := range m.IgnoredFindings {
		if sf.Hash != hash {
			filtered = append(filtered, sf)
		}
	}
	m.IgnoredFindings = filtered
	m.save()
}

func (m *Manager) load() {
	data, err := os.ReadFile(m.fpFile)
	if err != nil {
		return
	}
	var d fpData
	if err := json.Unmarshal(data, &d); err != nil {
		return
	}
	for _, h := range d.Hashes {
		m.ignoredHashes[h] = true
	}
	m.IgnoredFindings = d.Findings
}

func (m *Manager) save() {
	hashes := make([]string, 0, len(m.ignoredHashes))
	for h := range m.ignoredHashes {
		hashes = append(hashes, h)
	}
	d := fpData{
		Hashes:   hashes,
		Findings: m.IgnoredFindings,
	}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(m.fpFile, data, 0644)
}
