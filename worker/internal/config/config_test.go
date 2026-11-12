package config

import (
	"testing"
	"time"
)

func lookupFrom(m map[string]string) Lookup {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxCaptureSecs != 3600 || cfg.SSHDialTimeout != 10*time.Second {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(lookupFrom(map[string]string{
		"NETO_MAX_CAPTURE_SECS": "120",
		"NETO_SSH_DIAL_TIMEOUT": "3s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxCaptureSecs != 120 || cfg.SSHDialTimeout != 3*time.Second {
		t.Fatalf("unexpected: %+v", cfg)
	}
}

func TestLoadRejectsInvalid(t *testing.T) {
	for _, m := range []map[string]string{
		{"NETO_MAX_CAPTURE_SECS": "0"},
		{"NETO_MAX_CAPTURE_SECS": "abc"},
		{"NETO_MAX_CAPTURE_SECS": "999999"},
		{"NETO_SSH_DIAL_TIMEOUT": "-1s"},
	} {
		if _, err := Load(lookupFrom(m)); err == nil {
			t.Fatalf("expected error for %v", m)
		}
	}
}
