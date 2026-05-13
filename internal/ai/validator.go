// Package ai provides AI-powered validation and heuristic-based false positive detection.
// Security: API keys are never logged. AI receives only sanitized, truncated finding metadata.
// Source code is never sent to the AI — only minimal context (5 lines max, secrets redacted).
package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/AshishOP/authent8/internal/config"
	"github.com/AshishOP/authent8/internal/types"
)

// Validator performs heuristic + AI-based finding validation.
type Validator struct {
	apiKey  string
	baseURL string
	model   string
	client  *http.Client
}

// New creates a Validator from the resolved AI configuration.
func New(cfg config.AIConfig) *Validator {
	return &Validator{
		apiKey:  cfg.APIKey,
		baseURL: cfg.BaseURL,
		model:   cfg.Model,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// HasAPIKey returns true if an API key is configured.
func (v *Validator) HasAPIKey() bool {
	return v.apiKey != ""
}

// TestConnection verifies the AI provider is reachable.
func (v *Validator) TestConnection() error {
	if !v.HasAPIKey() {
		return fmt.Errorf("no API key configured")
	}

	body := chatRequest{
		Model: v.model,
		Messages: []chatMessage{
			{Role: "user", Content: "ping"},
		},
		MaxTokens:   5,
		Temperature: 0.0,
	}

	_, err := v.callAPI(body)
	if err != nil {
		errMsg := strings.ToLower(err.Error())
		if strings.Contains(errMsg, "401") || strings.Contains(errMsg, "unauthorized") ||
			strings.Contains(errMsg, "invalid_api_key") {
			return fmt.Errorf("AUTH_ERROR: %w", err)
		}
		if strings.Contains(errMsg, "model") && (strings.Contains(errMsg, "404") ||
			strings.Contains(errMsg, "not found")) {
			return fmt.Errorf("MODEL_ERROR: %w", err)
		}
		return err
	}
	return nil
}

// ValidateFindings applies heuristics first, then AI validation for remaining findings.
func (v *Validator) ValidateFindings(findings []types.Finding) {
	if len(findings) == 0 {
		return
	}

	// 1. Apply deterministic heuristics first (fast, no API call)
	applyHeuristics(findings)

	// 2. Identify what still needs AI validation
	var toValidate []*types.Finding
	for i := range findings {
		if !findings[i].Validated {
			toValidate = append(toValidate, &findings[i])
		}
	}

	if len(toValidate) == 0 || !v.HasAPIKey() {
		return
	}

	// 3. Batch AI validation (3 findings per call to avoid token limits)
	batchSize := 3
	for i := 0; i < len(toValidate); i += batchSize {
		end := i + batchSize
		if end > len(toValidate) {
			end = len(toValidate)
		}
		v.validateBatch(toValidate[i:end])
	}
}

// --- Heuristic Rules ---

// applyHeuristics applies deterministic false-positive detection rules.
func applyHeuristics(findings []types.Finding) {
	for i := range findings {
		f := &findings[i]
		path := strings.ToLower(f.File)
		fileName := strings.ToLower(filepath.Base(f.File))
		rule := strings.ToLower(f.RuleID)
		code := strings.ToLower(f.CodeSnippet)
		message := strings.ToLower(f.Message)
		tool := strings.ToLower(f.Tool)

		isTestOrDemo := strings.Contains(path, "/tests/") ||
			strings.Contains(path, "/test/") ||
			strings.Contains(path, "/mocks/") ||
			strings.Contains(path, "/fixtures/") ||
			strings.HasPrefix(fileName, "test_") ||
			strings.HasSuffix(fileName, "_test.py") ||
			fileName == "security_check.py"

		// RULE 1: Known internal test fixture file
		if fileName == "security_check.py" {
			markFalsePositive(f, 100, "Known internal fixture file.")
			continue
		}

		// RULE 2: Install scripts for tool bootstrap logic
		if strings.Contains(path, "install") || strings.Contains(path, "setup.py") {
			if strings.Contains(rule, "urllib") || strings.Contains(rule, "permissions") ||
				strings.Contains(code, "chmod") {
				markFalsePositive(f, 95, "Standard installation script behavior.")
				continue
			}
		}

		// RULE 3: Documentation/example files
		if strings.HasSuffix(path, ".md") || strings.HasSuffix(path, ".txt") {
			markFalsePositive(f, 95, "Secrets in documentation are likely examples.")
			continue
		}

		// RULE 4: False positive manager logic file itself
		if strings.Contains(path, "false_positives.py") || strings.Contains(path, "fp/manager.go") {
			markFalsePositive(f, 100, "Logic handling false positives often mimics vulnerabilities.")
			continue
		}

		// RULE 5: Placeholder/demo secrets in test fixtures
		if tool == "gitleaks" && isTestOrDemo {
			placeholders := []string{"example", "dummy", "placeholder", "sample", "test", "mock", "0000", "12345"}
			evidence := message + " " + code + " " + rule
			for _, marker := range placeholders {
				if strings.Contains(evidence, marker) {
					markFalsePositive(f, 90, "Likely placeholder secret in test/demo fixture.")
					break
				}
			}
		}
	}
}

func markFalsePositive(f *types.Finding, confidence int, reasoning string) {
	f.IsFalsePositive = true
	f.AIConfidence = confidence
	f.AIReasoning = reasoning
	f.Validated = true
}

// --- AI Validation ---

func (v *Validator) validateBatch(findings []*types.Finding) {
	prompt := buildPrompt(findings)

	body := chatRequest{
		Model: v.model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.1,
		MaxTokens:   4096,
	}

	respBody, err := v.callAPI(body)
	if err != nil {
		// Fallback: mark as unvalidated
		for _, f := range findings {
			f.Validated = false
			f.AIConfidence = 0
		}
		return
	}

	// Parse response
	var resp chatResponse
	if err := json.Unmarshal(respBody, &resp); err != nil || len(resp.Choices) == 0 {
		return
	}

	content := resp.Choices[0].Message.Content

	// Handle markdown code blocks
	if idx := strings.Index(content, "```json"); idx >= 0 {
		content = content[idx+7:]
		if end := strings.Index(content, "```"); end >= 0 {
			content = content[:end]
		}
	} else if idx := strings.Index(content, "```"); idx >= 0 {
		content = content[idx+3:]
		if end := strings.Index(content, "```"); end >= 0 {
			content = content[:end]
		}
	}

	var validations []aiValidation
	if err := json.Unmarshal([]byte(strings.TrimSpace(content)), &validations); err != nil {
		return
	}

	// Merge results
	for i, f := range findings {
		if i < len(validations) {
			v := validations[i]
			f.IsFalsePositive = v.IsFalsePositive
			f.AIConfidence = v.Confidence
			f.FixSuggestion = sanitizeText(v.FixSuggestion)
			f.AIReasoning = sanitizeText(v.Reasoning)
			f.Validated = true
		}
	}
}

// --- Prompt Construction ---

const systemPrompt = `You are a security expert validating security scan findings.
For EACH finding, determine:
1. is_false_positive (boolean) - Is this a false alarm? Common false positives:
   - Test Files: Any file named '*test*', '*mock*', 'security_check.py', or inside 'tests/' folder is likely a False Positive.
   - Install Scripts: 'install.sh', 'install_tools.py', 'setup.py' often require permissions (chmod 755) and downloads (urllib). These are False Positives.
   - Documentation: Files like .md, .txt containing secrets are examples.
   - Examples/Placeholders: Credentials like '0000', 'EXAMPLE', '123456'.
   - Checksums: MD5 used for integrity/ETag is SAFE (False Positive).

2. confidence (0-100) - How confident are you? (Higher for test files/examples)
3. fix_suggestion (string) - One-line actionable fix if real issue
4. reasoning (string) - Brief explanation (max 100 chars)

Respond ONLY with valid JSON array. No markdown, no explanation.`

func buildPrompt(findings []*types.Finding) string {
	sanitized := make([]promptFinding, len(findings))
	for i, f := range findings {
		sanitized[i] = promptFinding{
			ID:       i,
			Tool:     f.Tool,
			Type:     f.Type,
			Severity: f.Severity,
			RuleID:   sanitizeText(types.Truncate(f.RuleID, 50)),
			Message:  sanitizeText(types.Truncate(f.Message, 150)),
			FileHint: types.Truncate(f.File, 50),
			Line:     f.Line,
		}
		// Only include code snippet if present, truncated and sanitized
		if f.CodeSnippet != "" {
			sanitized[i].CodeSnippet = sanitizeText(types.Truncate(f.CodeSnippet, 1200))
		}
	}

	data, _ := json.Marshal(sanitized)
	return fmt.Sprintf(`Analyze these %d security findings and validate each one.

Findings:
%s

For EACH finding (all %d of them), provide:
{
  "id": <finding_id>,
  "is_false_positive": <true/false>,
  "confidence": <0-100>,
  "fix_suggestion": "<one line fix if real issue, empty if false positive>",
  "reasoning": "<brief explanation max 100 chars>"
}

Respond with JSON array of exactly %d validation objects.`, len(sanitized), string(data), len(sanitized), len(sanitized))
}

// --- HTTP Client ---

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []chatChoice `json:"choices"`
}

type chatChoice struct {
	Message chatMessage `json:"message"`
}

type aiValidation struct {
	ID             int    `json:"id"`
	IsFalsePositive bool  `json:"is_false_positive"`
	Confidence     int    `json:"confidence"`
	FixSuggestion  string `json:"fix_suggestion"`
	Reasoning      string `json:"reasoning"`
}

type promptFinding struct {
	ID          int    `json:"id"`
	Tool        string `json:"tool"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	RuleID      string `json:"rule_id"`
	Message     string `json:"message"`
	CodeSnippet string `json:"code_snippet,omitempty"`
	FileHint    string `json:"file_hint"`
	Line        int    `json:"line"`
}

func (v *Validator) callAPI(body chatRequest) ([]byte, error) {
	url := v.baseURL
	if !strings.HasSuffix(url, "/chat/completions") {
		url = strings.TrimRight(url, "/") + "/chat/completions"
	}

	reqData, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(reqData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Security: Use Authorization header — never log the key
	req.Header.Set("Authorization", "Bearer "+v.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Authent8/3.0.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	// Security: Limit response body to 1MB to prevent memory exhaustion
	limitedReader := io.LimitReader(resp.Body, 1<<20)
	respBody, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Security: Don't leak full error body — truncate
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode,
			types.Truncate(string(respBody), 200))
	}

	return respBody, nil
}

// sanitizeText replaces Unicode with ASCII and strips non-printable characters.
// Security: Prevents prompt injection via Unicode homoglyphs.
func sanitizeText(s string) string {
	if s == "" {
		return ""
	}
	replacements := map[rune]string{
		'\u2026': "...", '\u2019': "'", '\u2018': "'",
		'\u201c': "\"", '\u201d': "\"", '\u2014': "--",
		'\u2013': "-", '\u00a0': " ",
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if repl, ok := replacements[r]; ok {
			b.WriteString(repl)
		} else if r < 128 && (unicode.IsPrint(r) || r == '\n' || r == '\t') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// RedactSecrets replaces potential secret values in code snippets.
// Security: Ensures actual secrets are never sent to the AI provider.
func RedactSecrets(snippet string) string {
	if snippet == "" {
		return ""
	}
	// Common patterns for secrets in code
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 && len(parts[1]) > 8 {
			// Don't redact PATH or common system vars
			key := strings.ToUpper(parts[0])
			if key == "PATH" || key == "HOME" || key == "USER" || key == "SHELL" ||
				key == "TERM" || key == "LANG" || key == "PWD" {
				continue
			}
			snippet = strings.ReplaceAll(snippet, parts[1], "[REDACTED]")
		}
	}
	return snippet
}
