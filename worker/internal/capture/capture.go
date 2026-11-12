// Package capture runs tcpdump or NETOU (AF_PACKET fallback) on a remote host over an
// established SSH connection and streams the raw PCAP bytes to a writer.
//
// Binary data only ever goes to the writer; every diagnostic is an event on a separate channel.
// Nothing on the remote host is modified. Cleanup is therefore just "end the session".
package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"netorchestra/worker/internal/events"
	"netorchestra/worker/internal/spec"
)

// Backend identifies which capture tool is selected.
type Backend string

const (
	BackendTcpdump Backend = "tcpdump"
	BackendNetou   Backend = "NETOU (AF_PACKET)"
)

// Quote returns s as a single POSIX-shell word. Inputs are already allow-list validated;
// quoting is the second layer.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// BuildCommand builds the remote capture command for the chosen backend. `exec` replaces
// the shell so signals and stream closure reach the binary directly.
func BuildCommand(backend Backend, iface, filter string) string {
	if backend == BackendNetou {
		cmd := "exec netou -i " + Quote(iface)
		return cmd
	}
	// Default: tcpdump
	cmd := "exec tcpdump -n -U -s 0 -i " + Quote(iface) + " -w -"
	if filter != "" {
		cmd += " " + Quote(filter)
	}
	return cmd
}

// runShort executes a short diagnostic command and returns its stdout and exit status.
func runShort(ctx context.Context, c *ssh.Client, cmd string) (string, int, error) {
	sess, err := c.NewSession()
	if err != nil {
		return "", -1, err
	}
	defer sess.Close()
	stop := context.AfterFunc(ctx, func() { _ = sess.Close() })
	defer stop()
	out, err := sess.Output(cmd)
	if len(out) > 4096 {
		out = out[:4096]
	}
	var ee *ssh.ExitError
	switch {
	case err == nil:
		return string(out), 0, nil
	case errors.As(err, &ee):
		return string(out), ee.ExitStatus(), nil
	default:
		return string(out), -1, err
	}
}

// PreflightWithBackend verifies the remote interface exists, then checks whether tcpdump is
// operational. If tcpdump is missing or lacks capture permissions (cap_net_raw / root), it
// checks for NETOU. If NETOU is installed and has cap_net_raw, it selects BackendNetou.
// If neither is usable, it returns a descriptive error.
func PreflightWithBackend(ctx context.Context, c *ssh.Client, iface string) (Backend, error) {
	// 1. Verify remote interface exists
	if _, code, err := runShort(ctx, c, "test -d /sys/class/net/"+Quote(iface)); err != nil {
		return "", fmt.Errorf("preflight failed: %w", err)
	} else if code != 0 {
		return "", fmt.Errorf("interface %q does not exist on the remote host", iface)
	}

	// 2. Check tcpdump presence
	tcpdumpInstalled := false
	if _, code, err := runShort(ctx, c, "command -v tcpdump >/dev/null 2>&1"); err == nil && code == 0 {
		tcpdumpInstalled = true
	}

	tcpdumpErr := ""
	if tcpdumpInstalled {
		// Check tcpdump privileges: root (uid 0) or holds cap_net_raw
		out, _, err := runShort(ctx, c, `id -u; getcap "$(command -v tcpdump)" 2>/dev/null`)
		if err != nil {
			return "", fmt.Errorf("preflight failed checking tcpdump: %w", err)
		}
		lines := strings.SplitN(strings.TrimSpace(out), "\n", 2)
		uid := strings.TrimSpace(lines[0])
		caps := ""
		if len(lines) > 1 {
			caps = lines[1]
		}
		if uid == "0" || strings.Contains(caps, "cap_net_raw") {
			// tcpdump is fully operational
			return BackendTcpdump, nil
		}
		tcpdumpErr = "insufficient privileges for tcpdump: connect as root or grant tcpdump cap_net_raw (setcap cap_net_raw,cap_net_admin=eip $(command -v tcpdump)); sudo is deliberately not used"
	} else {
		tcpdumpErr = "tcpdump is not installed on the remote host"
	}

	// 3. Fallback to NETOU: check if netou is installed and operational
	netouInstalled := false
	if _, code, err := runShort(ctx, c, "command -v netou >/dev/null 2>&1"); err == nil && code == 0 {
		netouInstalled = true
	}

	if !netouInstalled {
		if !tcpdumpInstalled {
			return "", fmt.Errorf("no usable capture backend found: %s, and netou fallback is not installed on the remote host", tcpdumpErr)
		}
		return "", fmt.Errorf("%s; netou fallback is not installed on the remote host", tcpdumpErr)
	}

	// Test if netou can open AF_PACKET (netou -check)
	out, code, err := runShort(ctx, c, "netou -check")
	if err != nil || code != 0 {
		netouReason := strings.TrimSpace(out)
		if netouReason == "" {
			netouReason = "cannot open AF_PACKET socket (CAP_NET_RAW capability required)"
		}
		return "", fmt.Errorf("%s; NETOU fallback failed: %s (run: sudo setcap cap_net_raw+ep $(which netou))", tcpdumpErr, netouReason)
	}

	// NETOU is operational
	return BackendNetou, nil
}

// Preflight maintains backward compatibility by calling PreflightWithBackend and discarding the backend name.
func Preflight(ctx context.Context, c *ssh.Client, iface string) error {
	_, err := PreflightWithBackend(ctx, c, iface)
	return err
}

// Result summarises a finished capture.
type Result struct {
	Bytes   int64
	Reason  string // duration | user | size_limit | remote_exit | cancelled
	Backend Backend
}

// Stream captures until the duration elapses, stop is closed, the byte limit is reached, the
// context is cancelled or the remote command exits. out receives only PCAP bytes.
func Stream(ctx context.Context, c *ssh.Client, sp spec.Spec, out io.Writer, stop <-chan struct{}, emit *events.Emitter) (Result, error) {
	return StreamWithBackend(ctx, c, sp, BackendTcpdump, out, stop, emit)
}

// StreamWithBackend executes the capture using the specified backend.
func StreamWithBackend(ctx context.Context, c *ssh.Client, sp spec.Spec, backend Backend, out io.Writer, stop <-chan struct{}, emit *events.Emitter) (Result, error) {
	sess, err := c.NewSession()
	if err != nil {
		return Result{Backend: backend}, fmt.Errorf("cannot open session: %w", err)
	}
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return Result{Backend: backend}, err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return Result{Backend: backend}, err
	}
	if err := sess.Start(BuildCommand(backend, sp.Interface, sp.Filter)); err != nil {
		return Result{Backend: backend}, fmt.Errorf("cannot start remote capture with %s: %w", backend, err)
	}

	var (
		mu       sync.Mutex
		total    int64
		limitHit = make(chan struct{})
		once     sync.Once
		wg       sync.WaitGroup
		errTail  strings.Builder
		copyErr  error
	)
	getTotal := func() int64 { mu.Lock(); defer mu.Unlock(); return total }

	wg.Add(2)
	go func() { // stdout -> out (bounded 64 KiB buffer)
		defer wg.Done()
		buf := make([]byte, 64*1024)
		for {
			n, rerr := stdout.Read(buf)
			if n > 0 {
				if _, werr := out.Write(buf[:n]); werr != nil {
					copyErr = fmt.Errorf("output closed: %w", werr)
					once.Do(func() { close(limitHit) })
					return
				}
				mu.Lock()
				total += int64(n)
				hit := total >= sp.MaxBytes
				mu.Unlock()
				if hit {
					once.Do(func() { close(limitHit) })
				}
			}
			if rerr != nil {
				return
			}
		}
	}()
	go func() { // remote stderr: keep a short tail for error messages
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			n, rerr := stderr.Read(buf)
			if n > 0 && errTail.Len() < 2048 {
				errTail.Write(buf[:n])
			}
			if rerr != nil {
				return
			}
		}
	}()

	exited := make(chan error, 1)
	go func() { exited <- sess.Wait() }()

	timer := time.NewTimer(time.Duration(sp.DurationSecs) * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()

	reason := ""
	var waitErr error
	waited := false
loop:
	for {
		select {
		case <-tick.C:
			emit.Emit("progress", map[string]any{"bytes": getTotal()})
		case <-timer.C:
			reason = "duration"
			break loop
		case <-stop:
			reason = "user"
			break loop
		case <-limitHit:
			reason = "size_limit"
			break loop
		case <-ctx.Done():
			reason = "cancelled"
			break loop
		case waitErr = <-exited:
			reason, waited = "remote_exit", true
			break loop
		}
	}

	if !waited {
		// Signal to finish cleanly, then force-close if it ignores us.
		_ = sess.Signal(ssh.SIGINT)
		select {
		case waitErr = <-exited:
		case <-time.After(5 * time.Second):
			_ = sess.Close()
			select {
			case waitErr = <-exited:
			case <-time.After(2 * time.Second):
			}
		}
	}
	// Drain what is left in the pipes, but never hang on a stuck remote.
	drained := make(chan struct{})
	go func() { wg.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		_ = sess.Close()
		<-drained
	}

	res := Result{Bytes: getTotal(), Reason: reason, Backend: backend}
	if copyErr != nil {
		return res, copyErr
	}
	if reason == "remote_exit" && waitErr != nil {
		msg := strings.TrimSpace(errTail.String())
		if msg == "" {
			msg = waitErr.Error()
		}
		return res, fmt.Errorf("remote capture failed: %s", firstLine(msg, 300))
	}
	return res, nil
}

func firstLine(s string, max int) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > max {
		s = s[:max]
	}
	return s
}
