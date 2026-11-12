// Package spec defines the capture job specification sent by the backend on stdin and
// validates it. The backend validates the same fields; the worker re-validates because it
// builds a command that runs on a remote host and must not trust its caller.
package spec

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Spec is one capture job. Secrets are never part of it: CredentialRef only names a key
// file inside the worker's configured keys directory.
type Spec struct {
	JobID         string `json:"job_id"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	CredentialRef string `json:"credential_ref"`
	Password      string `json:"password,omitempty"`
	Interface     string `json:"interface"`
	DurationSecs  int    `json:"duration_secs"`
	Filter        string `json:"filter"`
	MaxBytes      int64  `json:"max_bytes"`
}

var (
	userRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)
	credRe  = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}$`)
	ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,32}$`)
	// BPF expressions: no quotes, backticks, $, ;, backslashes, newlines or braces.
	filterRe = regexp.MustCompile(`^[A-Za-z0-9 .:/()!=<>&|_\[\]-]{0,512}$`)
	jobRe    = regexp.MustCompile(`^[0-9a-fA-F-]{8,40}$`)
)

// Validate checks every field against a strict allow-list.
func (s *Spec) Validate(maxDuration int) error {
	if !jobRe.MatchString(s.JobID) {
		return errors.New("invalid job_id")
	}
	if net.ParseIP(s.Host) == nil {
		return errors.New("host must be an IP address")
	}
	if s.Port < 1 || s.Port > 65535 {
		return errors.New("port out of range")
	}
	if !userRe.MatchString(s.Username) {
		return errors.New("invalid username")
	}
	if !credRe.MatchString(s.CredentialRef) || strings.Contains(s.CredentialRef, "..") {
		if s.Password == "" {
			return errors.New("credential_ref or password is required")
		}
	}
	if !ifaceRe.MatchString(s.Interface) {
		return errors.New("invalid interface")
	}
	if !filterRe.MatchString(s.Filter) {
		return errors.New("invalid capture filter")
	}
	if s.DurationSecs < 1 || (maxDuration > 0 && s.DurationSecs > maxDuration) {
		return fmt.Errorf("duration_secs must be between 1 and %d", maxDuration)
	}
	if s.MaxBytes < 1 {
		return errors.New("max_bytes must be positive")
	}
	return nil
}
