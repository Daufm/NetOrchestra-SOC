// Package testsupport provides an in-process SSH server for tests (mock "remote host").
package testsupport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ExecHandler emulates one remote command. It must return when the command finishes; a
// received signal name (e.g. "INT") arrives on signals.
type ExecHandler func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32

// Server is a running mock SSH server plus the files a client needs to talk to it.
type Server struct {
	Host, Port string
	HostKey    ssh.PublicKey
	KnownHosts string // known_hosts file containing the server's real key
	KeysDir    string
	Ref        string // credential_ref of the authorised private key
	ClientKey  ssh.Signer
	ln         net.Listener
	wg         sync.WaitGroup
}

func (s *Server) PortInt() int { p, _ := strconv.Atoi(s.Port); return p }

// Dial connects to the mock SSH server using the test client key.
func (s *Server) Dial(ctx context.Context) (*ssh.Client, error) {
	if s.ClientKey == nil {
		return nil, os.ErrInvalid
	}
	cfg := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(s.ClientKey),
		},
		HostKeyCallback: ssh.FixedHostKey(s.HostKey),
		Timeout:         5 * time.Second,
	}
	addr := net.JoinHostPort(s.Host, s.Port)
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
			if err != nil {
		return nil, err
			}
	return ssh.NewClient(sshConn, chans, reqs), nil
		}

func writeKey(t testing.TB, path string, mode os.FileMode, priv ed25519.PrivateKey) {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), mode); err != nil {
		t.Fatal(err)
	}
}

// Start launches the server. Cleanup is registered on t.
func Start(t testing.TB, handler ExecHandler) *Server {
	t.Helper()
	dir := t.TempDir()
	hostPub, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientSSHPub, _ := ssh.NewPublicKey(clientPub)
	clientSigner, _ := ssh.NewSignerFromKey(clientPriv)
	_ = hostPub

	keysDir := filepath.Join(dir, "keys")
	if err := os.Mkdir(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeKey(t, filepath.Join(keysDir, "soc-key"), 0o600, clientPriv)

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(clientSSHPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, os.ErrPermission
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	s := &Server{Host: host, Port: port, HostKey: hostSigner.PublicKey(), KeysDir: keysDir, Ref: "soc-key", ClientKey: clientSigner, ln: ln}

	line := knownhosts.Line([]string{knownhosts.Normalize(ln.Addr().String())}, hostSigner.PublicKey())
	s.KnownHosts = filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(s.KnownHosts, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() { defer s.wg.Done(); serve(conn, cfg, handler) }()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); s.wg.Wait() })
	return s
}

func serve(conn net.Conn, cfg *ssh.ServerConfig, handler ExecHandler) {
	defer conn.Close()
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go session(ch, creqs, handler)
	}
}

func session(ch ssh.Channel, reqs <-chan *ssh.Request, handler ExecHandler) {
	signals := make(chan string, 4)
	for req := range reqs {
		switch req.Type {
		case "exec":
			var p struct{ Command string }
			if ssh.Unmarshal(req.Payload, &p) != nil {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			go func() {
				status := handler(p.Command, ch, ch.Stderr(), signals)
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
				_ = ch.Close()
			}()
		case "signal":
			var p struct{ Signal string }
			if ssh.Unmarshal(req.Payload, &p) == nil {
				select {
				case signals <- p.Signal:
				default:
			}
	}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

