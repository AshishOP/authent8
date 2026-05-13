// Package history manages scan history persistence in ~/.authent8_history.json.
package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const maxHistory = 10

// Entry represents a single scan history record.
type Entry struct {
	Path      string  `json:"path"`
	Timestamp string  `json:"timestamp"`
	Findings  int     `json:"findings"`
	Critical  int     `json:"critical"`
	High      int     `json:"high"`
	Duration  float64 `json:"duration"`
}

func historyFile() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".authent8_history.json")
}

// Load reads the scan history from disk.
func Load() []Entry {
	data, err := os.ReadFile(historyFile())
	if err != nil {
		return nil
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil
	}
	return entries
}

// Save writes the scan history to disk, keeping only the last maxHistory entries.
func Save(entries []Entry) {
	if len(entries) > maxHistory {
		entries = entries[len(entries)-maxHistory:]
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(historyFile(), data, 0644)
}

// Add appends a new scan entry and persists.
func Add(path string, findings, critical, high int, duration float64) {
	entries := Load()
	entries = append(entries, Entry{
		Path:      path,
		Timestamp: time.Now().Format(time.RFC3339),
		Findings:  findings,
		Critical:  critical,
		High:      high,
		Duration:  duration,
	})
	Save(entries)
}

// Recent returns the last n entries in reverse chronological order.
func Recent(n int) []Entry {
	entries := Load()
	if len(entries) == 0 {
		return nil
	}
	if n > len(entries) {
		n = len(entries)
	}
	// Reverse the last n entries
	result := make([]Entry, n)
	for i := 0; i < n; i++ {
		result[i] = entries[len(entries)-1-i]
	}
	return result
}
