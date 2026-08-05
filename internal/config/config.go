package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds all runtime configuration for a ThreatLens run.
type Config struct {
	Concurrency int      `yaml:"concurrency"`
	TimeoutSecs int      `yaml:"timeout_seconds"`
	Retries     int      `yaml:"retries"`
	Proxy       string   `yaml:"proxy"`
	UserAgent   string   `yaml:"user_agent"`
	KnowledgeDB string   `yaml:"knowledge_db_path"`
	OutputDir   string   `yaml:"output_dir"`
	Verbosity   string   `yaml:"verbosity"`
	Targets     []string `yaml:"targets"`
	AI          AIConfig `yaml:"ai"`
}

// AIConfig holds optional AI provider settings.
// API keys are read from environment variables, never stored here.
type AIConfig struct {
	Provider string `yaml:"provider"` // openai | anthropic | ollama | gemini
	Model    string `yaml:"model"`
	BaseURL  string `yaml:"base_url"`
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		Concurrency: 5,
		TimeoutSecs: 30,
		Retries:     3,
		UserAgent:   "ThreatLens/1.0",
		OutputDir:   "./reports",
		Verbosity:   "info",
	}
}

// Load reads a YAML config file and merges it over the defaults.
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}

	return cfg, nil
}

// Validate checks that required fields have acceptable values.
func (c *Config) Validate() error {
	if c.Concurrency < 1 {
		return fmt.Errorf("config: concurrency must be >= 1")
	}
	if c.TimeoutSecs < 1 {
		return fmt.Errorf("config: timeout_seconds must be >= 1")
	}
	return nil
}
