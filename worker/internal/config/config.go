// Package config loads worker configuration from the environment.
// Secrets (SSH keys, tokens) are never hardcoded; later phases reference them by path or ID.
package config

import (
	"fmt"
	"strconv"
	"time"
)

// Config holds worker runtime settings.
type Config struct {
	BackendURL      string
	EvidenceDir     string
	KeysDir         string
	KnownHosts      string
	SSHDialTimeout  time.Duration
	MaxCaptureSecs  int
	ShutdownTimeout time.Duration
}

// Lookup resolves an environment variable; injectable for tests.
type Lookup func(key string) (string, bool)

// Load builds a Config from the given lookup, applying defaults and validating bounds.
func Load(get Lookup) (Config, error) {
	cfg := Config{
		BackendURL:      "http://backend:8080",
		EvidenceDir:     "/var/lib/netorchestra/evidence",
		KeysDir:         "",
		KnownHosts:      "",
		SSHDialTimeout:  10 * time.Second,
		MaxCaptureSecs:  3600,
		ShutdownTimeout: 15 * time.Second,
	}
	if v, ok := get("NETO_BACKEND_URL"); ok && v != "" {
		cfg.BackendURL = v
	}
	if v, ok := get("NETO_EVIDENCE_DIR"); ok && v != "" {
		cfg.EvidenceDir = v
	}
	if v, ok := get("NETO_WORKER_KEYS_DIR"); ok {
		cfg.KeysDir = v
	}
	if v, ok := get("NETO_WORKER_KNOWN_HOSTS"); ok {
		cfg.KnownHosts = v
	}
	if v, ok := get("NETO_MAX_CAPTURE_SECS"); ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 86400 {
			return Config{}, fmt.Errorf("NETO_MAX_CAPTURE_SECS %q: must be an integer in 1..86400", v)
		}
		cfg.MaxCaptureSecs = n
	}
	if v, ok := get("NETO_SSH_DIAL_TIMEOUT"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("NETO_SSH_DIAL_TIMEOUT %q: must be a positive duration", v)
		}
		cfg.SSHDialTimeout = d
	}
	return cfg, nil
}
