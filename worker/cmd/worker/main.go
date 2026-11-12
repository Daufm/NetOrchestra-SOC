// Command worker is the NetOrchestra remote packet-acquisition worker.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"netorchestra/worker/internal/capture"
	"netorchestra/worker/internal/config"
	"netorchestra/worker/internal/events"
	"netorchestra/worker/internal/spec"
	"netorchestra/worker/internal/sshclient"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Stdin, os.Stdout, os.Stderr, os.LookupEnv))
}

func run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, env config.Lookup) int {
	emit := events.New(stderr)
	cfg, err := config.Load(env)
	if err != nil {
		emit.Emit("error", map[string]any{"message": err.Error()})
		return 2
	}

	reader := bufio.NewReader(stdin)
	line, err := readLine(reader, 64*1024)
	if err != nil {
		emit.Emit("error", map[string]any{"message": fmt.Sprintf("invalid spec input: %v", err)})
		return 2
	}
	var sp spec.Spec
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sp); err != nil {
		emit.Emit("error", map[string]any{"message": fmt.Sprintf("invalid spec: %v", err)})
		return 2
	}
	if err := sp.Validate(86400); err != nil {
		emit.Emit("error", map[string]any{"message": err.Error()})
		return 2
	}

	stopCapture := make(chan struct{})
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { close(stopCapture) }) }
	go readCommands(reader, stop)

	dialCtx, cancel := context.WithTimeout(ctx, cfg.SSHDialTimeout)
	defer cancel()
	client, err := sshclient.Dial(dialCtx, sshclient.Config{
		Host: sp.Host, Port: sp.Port, Username: sp.Username,
		CredentialRef: sp.CredentialRef, Password: sp.Password, KeysDir: cfg.KeysDir,
		KnownHosts: cfg.KnownHosts, DialTimeout: cfg.SSHDialTimeout,
	})
	if err != nil {
		emit.Emit("error", map[string]any{"message": err.Error()})
		return 1
	}
	defer client.Close()

	cleanupOnce := sync.Once{}
	defer cleanupOnce.Do(func() { emit.Emit("cleanup", nil) })

	backend, err := capture.PreflightWithBackend(ctx, client.Client, sp.Interface)
	if err != nil {
		emit.Emit("error", map[string]any{"message": err.Error()})
		return 1
	}
	emit.Emit("started", map[string]any{
		"host_key": client.HostKeyFingerprint,
		"backend":  string(backend),
	})
	result, err := capture.StreamWithBackend(ctx, client.Client, sp, backend, stdout, stopCapture, emit)
	if err != nil {
		emit.Emit("error", map[string]any{"message": err.Error()})
		return 1
	}
	emit.Emit("stopped", map[string]any{"reason": result.Reason, "bytes": result.Bytes})
	return 0
}

func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		line = append(line, part...)
		if len(line) > max {
			return nil, fmt.Errorf("line exceeds %d bytes", max)
		}
		if err == nil {
			return bytes.TrimSpace(line), nil
		}
		if err != bufio.ErrBufferFull {
			if err == io.EOF && len(line) > 0 {
				return bytes.TrimSpace(line), nil
			}
			return nil, err
		}
	}
}

func readCommands(r io.Reader, stop func()) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		var command struct {
			Cmd string `json:"cmd"`
		}
		if json.Unmarshal(scanner.Bytes(), &command) == nil && command.Cmd == "stop" {
			stop()
			return
		}
	}
	stop()
}
