package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"netorchestra/worker/internal/testsupport"
)

func echo(cmd string, stdout, stderr io.Writer, sig <-chan string) uint32 {
	_, _ = io.WriteString(stdout, "ok\n")
	return 0
}

func cfgFor(s *testsupport.Server) Config {
	return Config{Host: s.Host, Port: s.PortInt(), Username: "capture", CredentialRef: s.Ref,
		KeysDir: s.KeysDir, KnownHosts: s.KnownHosts, DialTimeout: 5 * time.Second}
}

func TestConnectsWhenHostKeyIsKnown(t *testing.T) {
	s := testsupport.Start(t, echo)
	c, err := Dial(context.Background(), cfgFor(s))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !strings.HasPrefix(c.HostKeyFingerprint, "SHA256:") {
		t.Fatalf("fingerprint = %q", c.HostKeyFingerprint)
	}
	if c.HostKeyFingerprint != ssh.FingerprintSHA256(s.HostKey) {
		t.Fatal("fingerprint does not match the server key")
	}
}

func TestRefusesUnknownHost(t *testing.T) {
	s := testsupport.Start(t, echo)
	cfg := cfgFor(s)
	empty := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.KnownHosts = empty
	_, err := Dial(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "not in known_hosts") {
		t.Fatalf("expected unknown-host refusal, got %v", err)
	}
}

func TestRefusesChangedHostKey(t *testing.T) {
	s := testsupport.Start(t, echo)
	cfg := cfgFor(s)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewPublicKey(otherPub)
	line := knownhosts.Line([]string{knownhosts.Normalize(s.Host + ":" + s.Port)}, other)
	bad := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(bad, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.KnownHosts = bad
	_, err := Dial(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected key-mismatch refusal, got %v", err)
	}
}

func TestRequiresKnownHostsFile(t *testing.T) {
	s := testsupport.Start(t, echo)
	cfg := cfgFor(s)
	cfg.KnownHosts = ""
	if _, err := Dial(context.Background(), cfg); err == nil {
		t.Fatal("must refuse to connect without known_hosts")
	}
	cfg.KnownHosts = filepath.Join(t.TempDir(), "missing")
	if _, err := Dial(context.Background(), cfg); err == nil {
		t.Fatal("must refuse a missing known_hosts file")
	}
}

func TestRefusesUnauthorisedKey(t *testing.T) {
	s := testsupport.Start(t, echo)
	cfg := cfgFor(s)
	other := testsupport.Start(t, echo) // a different server's client key is not authorised here
	cfg.KeysDir, cfg.CredentialRef = other.KeysDir, other.Ref
	if _, err := Dial(context.Background(), cfg); err == nil {
		t.Fatal("expected authentication failure")
	}
}

func TestHashedKnownHostsEntries(t *testing.T) {
	s := testsupport.Start(t, echo)
	cfg := cfgFor(s)
	addr := knownhosts.Normalize(s.Host + ":" + s.Port)
	line := knownhosts.Line([]string{knownhosts.HashHostname(addr)}, s.HostKey)
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.KnownHosts = p
	c, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatalf("hashed entry should be honoured: %v", err)
	}
	c.Close()
}

func TestCredentialSafety(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	pemBytes := []byte(string(pemEncode(block)))

	write := func(name string, mode os.FileMode, data []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), data, mode); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(filepath.Join(dir, name), mode)
	}
	write("good", 0o600, pemBytes)
	write("loose", 0o644, pemBytes)
	write("group", 0o640, pemBytes)
	write("garbage", 0o600, []byte("not a key"))
	if err := os.Symlink(filepath.Join(dir, "good"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	encBlock, _ := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("pw"))
	write("encrypted", 0o600, pemEncode(encBlock))

	if _, err := LoadSigner(dir, "good"); err != nil {
		t.Fatalf("good key rejected: %v", err)
	}
	for name, ref := range map[string]string{
		"world-readable": "loose", "group-readable": "group", "garbage": "garbage", "symlink": "link",
		"encrypted": "encrypted", "missing": "nope", "traversal": "../good", "slash": "a/b", "hidden": ".good", "empty": "",
	} {
		if _, err := LoadSigner(dir, ref); err == nil {
			t.Errorf("%s: expected refusal", name)
		}
	}
	if _, err := LoadSigner("", "good"); err == nil {
		t.Error("empty keys dir must be refused")
	}
}

func TestDialHonoursCancellation(t *testing.T) {
	s := testsupport.Start(t, echo)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Dial(ctx, cfgFor(s)); err == nil {
		t.Fatal("cancelled context must abort the dial")
	}
}
