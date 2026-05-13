// Package config handles loading Authent8 configuration from environment
// variables and .authent8.env files, supporting 9 AI providers.
package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
)

// AIConfig holds the resolved AI provider configuration.
type AIConfig struct {
	Provider string `json:"provider"`
	APIKey   string `json:"api_key"`
	Model    string `json:"model"`
	BaseURL  string `json:"base_url"`
}

// ProviderInfo describes a supported AI provider.
type ProviderInfo struct {
	Name    string
	BaseURL string
	Models  []string
}

// Providers is the registry of supported AI providers.
var Providers = map[string]ProviderInfo{
	"OpenAI": {
		Name:    "OpenAI",
		BaseURL: "https://api.openai.com/v1",
		Models:  []string{"gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"},
	},
	"Anthropic (via OpenAI compat)": {
		Name:    "Anthropic",
		BaseURL: "https://api.anthropic.com/v1",
		Models:  []string{"claude-sonnet-4-20250514", "claude-3-5-haiku-20241022"},
	},
	"Google Gemini": {
		Name:    "Gemini",
		BaseURL: "https://generativelanguage.googleapis.com/v1beta/openai",
		Models:  []string{"gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"},
	},
	"GitHub Models": {
		Name:    "GitHub Models",
		BaseURL: "https://models.inference.ai.azure.com",
		Models:  []string{"gpt-4o", "gpt-4o-mini"},
	},
	"Groq": {
		Name:    "Groq",
		BaseURL: "https://api.groq.com/openai/v1",
		Models:  []string{"llama-3.3-70b-versatile", "mixtral-8x7b-32768"},
	},
	"Mistral": {
		Name:    "Mistral",
		BaseURL: "https://api.mistral.ai/v1",
		Models:  []string{"mistral-large-latest", "mistral-small-latest"},
	},
	"Ollama (Local)": {
		Name:    "Ollama",
		BaseURL: "http://localhost:11434/v1",
		Models:  []string{"llama3", "codellama", "mistral"},
	},
	"Perplexity": {
		Name:    "Perplexity",
		BaseURL: "https://api.perplexity.ai",
		Models:  []string{"llama-3.1-sonar-large-128k-online"},
	},
	"Custom (OpenAI Compatible)": {
		Name:    "Custom",
		BaseURL: "",
		Models:  nil,
	},
}

// Load reads .authent8.env files from standard locations.
// Priority: CWD > ~/.authent8.env > existing env vars.
func Load() {
	// 1. Home directory
	home, err := os.UserHomeDir()
	if err == nil {
		_ = godotenv.Load(filepath.Join(home, ".authent8.env"))
	}
	// 2. Current working directory (overrides home)
	_ = godotenv.Load()
}

// GetAIConfig resolves the active AI configuration from environment.
func GetAIConfig() AIConfig {
	apiKey := firstNonEmpty(
		os.Getenv("AUTHENT8_AI_KEY"),
		os.Getenv("FASTROUTER_API_KEY"),
		os.Getenv("OPENAI_API_KEY"),
		os.Getenv("GITHUB_TOKEN"),
	)
	// Reject placeholder keys
	if strings.HasPrefix(apiKey, "your-") {
		apiKey = ""
	}

	baseURL := firstNonEmpty(
		os.Getenv("AUTHENT8_AI_BASE_URL"),
		os.Getenv("FASTROUTER_API_HOST"),
		os.Getenv("OPENAI_BASE_URL"),
	)

	// GitHub Models fallback
	if baseURL == "" && os.Getenv("GITHUB_TOKEN") != "" &&
		os.Getenv("OPENAI_API_KEY") == "" && os.Getenv("AUTHENT8_AI_KEY") == "" {
		baseURL = "https://models.inference.ai.azure.com"
	}

	model := firstNonEmpty(
		os.Getenv("AUTHENT8_AI_MODEL"),
		os.Getenv("AI_MODEL"),
	)
	if model == "" {
		model = "gpt-4o-mini"
	}

	provider := os.Getenv("AUTHENT8_AI_PROVIDER")
	if provider == "" {
		provider = "Auto-detected"
	}

	return AIConfig{
		Provider: provider,
		APIKey:   apiKey,
		Model:    model,
		BaseURL:  baseURL,
	}
}

// SaveConfig writes key-value pairs to ~/.authent8.env.
func SaveConfig(values map[string]string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	envPath := filepath.Join(home, ".authent8.env")

	// Load existing values
	existing, _ := godotenv.Read(envPath)
	if existing == nil {
		existing = make(map[string]string)
	}

	// Merge new values
	for k, v := range values {
		existing[k] = v
	}

	return godotenv.Write(existing, envPath)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
