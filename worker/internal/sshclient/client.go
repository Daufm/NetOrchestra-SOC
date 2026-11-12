// Package sshclient opens SSH connections with strict host-key verification and
// private-key or password authentication. There is no "accept new host key" mode and no
// InsecureIgnoreHostKey anywhere.
package sshclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Config describes one connection.
type Config struct {
	Host          string
	Port          int
	Username      string
	CredentialRef string
	Password      string
	KeysDir       string        // directory containing private key files named by CredentialRef
	KnownHosts    string        // path to a known_hosts file; required
	DialTimeout   time.Duration // TCP connect + SSH handshake
}

// Client wraps an established connection.
type Client struct {
	*ssh.Client
	// HostKeyFingerprint is the SHA256 fingerprint of the verified server key.
	HostKeyFingerprint string
}

// LoadSigner reads the private key for a credential reference. The reference is validated
// again here, the file must be a regular, non-symlink file readable only by its owner,
// and encrypted keys are refused (the worker has no way to prompt for a passphrase).
func LoadSigner(keysDir, ref string) (ssh.Signer, error) {
	if keysDir == "" {
		return nil, errors.New("NETO_WORKER_KEYS_DIR is not configured")
	}
	if ref == "" || strings.ContainsAny(ref, "/\\") || strings.Contains(ref, "..") || strings.HasPrefix(ref, ".") {
		return nil, errors.New("invalid credential reference")
	}
	path := filepath.Join(keysDir, ref)
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("credential %q not found", ref)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("credential %q must be a regular file (symlinks are refused)", ref)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("credential %q has unsafe permissions %o: restrict to 0600", ref, fi.Mode().Perm())
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read credential %q", ref)
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		var pm *ssh.PassphraseMissingError
		if errors.As(err, &pm) {
			return nil, fmt.Errorf("credential %q is passphrase-protected; use an unencrypted key restricted to capture", ref)
		}
		return nil, fmt.Errorf("credential %q is not a valid private key", ref)
	}
	return signer, nil
}

// Dial connects and authenticates. The server host key must already be present in the
// known_hosts file; otherwise the connection is refused.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.KnownHosts == "" {
		return nil, errors.New("NETO_WORKER_KNOWN_HOSTS is not configured: strict host-key verification is mandatory")
	}
	if _, err := os.Stat(cfg.KnownHosts); err != nil {
		return nil, fmt.Errorf("known_hosts file unavailable: %w", err)
	}
	verify, err := knownhosts.New(cfg.KnownHosts)
	if err != nil {
		return nil, fmt.Errorf("cannot parse known_hosts: %w", err)
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	var fingerprint string
	callback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if err := verify(hostname, remote, key); err != nil {
			var ke *knownhosts.KeyError
			if errors.As(err, &ke) && len(ke.Want) == 0 {
				return fmt.Errorf("host key verification failed: %s is not in known_hosts (fingerprint %s)", addr, ssh.FingerprintSHA256(key))
			}
			return fmt.Errorf("host key verification failed for %s: key does not match known_hosts (possible interception)", addr)
		}
		fingerprint = ssh.FingerprintSHA256(key)
		return nil
	}
	auth := ssh.AuthMethod(nil)
	if cfg.Password != "" {
		auth = ssh.Password(cfg.Password)
	} else {
		signer, err := LoadSigner(cfg.KeysDir, cfg.CredentialRef)
		if err != nil {
			return nil, err
		}
		auth = ssh.PublicKeys(signer)
	}
	sshCfg := &ssh.ClientConfig{
		User:              cfg.Username,
		Auth:              []ssh.AuthMethod{auth},
		HostKeyCallback:   callback,
		HostKeyAlgorithms: algorithmsFor(cfg.KnownHosts, knownhosts.Normalize(addr)),
		Timeout:           cfg.DialTimeout,
	}

	d := net.Dialer{Timeout: cfg.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to %s: %w", addr, err)
	}
	// The handshake has no context support, so bound it with a deadline and honour cancellation.
	_ = conn.SetDeadline(time.Now().Add(cfg.DialTimeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, sshCfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake with %s failed: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return &Client{Client: ssh.NewClient(sc, chans, reqs), HostKeyFingerprint: fingerprint}, nil
}
