import os
from pathlib import Path
from dotenv import load_dotenv, set_key

# Configuration file location
CONFIG_PATH = Path.home() / ".authent8.env"

def load_config():
    """Load configuration from ~/.authent8.env"""
    if CONFIG_PATH.exists():
        load_dotenv(CONFIG_PATH)
    else:
        # Create empty file if not exists
        CONFIG_PATH.touch()

def save_config(updates: dict):
    """Save key-value pairs to ~/.authent8.env"""
    if not CONFIG_PATH.exists():
        CONFIG_PATH.touch()
        
    for key, value in updates.items():
        set_key(str(CONFIG_PATH), key, value)

def get_ai_config():
    """Get current AI configuration"""
    # Load fresh from file
    load_config()
    return {
        "provider": os.getenv("AUTHENT8_AI_PROVIDER", "OpenAI"),
        "api_key": os.getenv("AUTHENT8_AI_KEY") or os.getenv("OPENAI_API_KEY"),
        "model": os.getenv("AUTHENT8_AI_MODEL") or os.getenv("AI_MODEL", "gpt-4o-mini"),
        "base_url": os.getenv("AUTHENT8_AI_BASE_URL") or os.getenv("OPENAI_BASE_URL"),
    }

PROVIDERS = {
    "OpenAI": {
        "base_url": None,
        "models": ["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"],
        "env_key": "OPENAI_API_KEY"
    },
    "Anthropic (Direct)": {
        "base_url": "https://api.anthropic.com/v1", # Note: Anthropic needs specific headers usually
        "models": ["claude-3-5-sonnet-20240620", "claude-3-haiku-20240307"],
        "env_key": "ANTHROPIC_API_KEY"
    },
    "Google Gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "models": ["gemini-1.5-flash", "gemini-1.5-pro"],
        "env_key": "GEMINI_API_KEY"
    },
    "GitHub Models (Inference)": {
        "base_url": "https://models.inference.ai.azure.com",
        "models": ["gpt-4o", "meta-llama-3-70b-instruct", "cohere-command-r-plus"],
        "env_key": "GITHUB_TOKEN"
    },
    "Groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "models": ["llama3-8b-8192", "mixtral-8x7b-32768", "llama3-70b-8192"],
        "env_key": "GROQ_API_KEY"
    },
    "Mistral AI": {
        "base_url": "https://api.mistral.ai/v1",
        "models": ["mistral-large-latest", "open-mixtral-8x22b", "mistral-small-latest"],
        "env_key": "MISTRAL_API_KEY"
    },
    "Perplexity": {
        "base_url": "https://api.perplexity.ai",
        "models": ["llama-3-sonar-large-32k-online", "llama-3-sonar-small-32k-chat"],
        "env_key": "PERPLEXITY_API_KEY"
    },
    "Ollama (Local)": {
        "base_url": "http://localhost:11434/v1",
        "models": ["llama3", "mistral", "phi3"],
        "env_key": "OLLAMA_API_KEY"
    },
    "Custom (OpenAI Compatible)": {
        "base_url": "",
        "models": [],
        "env_key": "OPENAI_API_KEY"
    }
}
