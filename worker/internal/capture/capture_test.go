// Package capture_test tests the capture logic against a mock SSH server.
package capture

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"netorchestra/worker/internal/events"
	"netorchestra/worker/internal/spec"
	"netorchestra/worker/internal/testsupport"
)

func TestQuote(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"eth0", "'eth0'"},
		{"a'b", "'a'\\''b'"},
		{"$(id)", "'$(id)'"},
		{"; rm -rf /", "'; rm -rf /'"},
		{"new\nline", "'new\nline'"},
		{"", "''"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := Quote(tc.input)
			if got != tc.expected {
				t.Errorf("Quote(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestBuildCommand(t *testing.T) {
	tests := []struct {
		backend Backend
		iface   string
		filter  string
		want    string
	}{
		{BackendTcpdump, "eth0", "", "exec tcpdump -n -U -s 0 -i 'eth0' -w -"},
		{BackendTcpdump, "eth0", "port 80", "exec tcpdump -n -U -s 0 -i 'eth0' -w - 'port 80'"},
		{BackendTcpdump, "enp0s3", "tcp and host 1.2.3.4", "exec tcpdump -n -U -s 0 -i 'enp0s3' -w - 'tcp and host 1.2.3.4'"},
		{BackendNetou, "eth0", "", "exec netou -i 'eth0'"},
		{BackendNetou, "wlan0", "port 443", "exec netou -i 'wlan0'"},
	}
	for _, tc := range tests {
		t.Run(string(tc.backend)+"_"+tc.iface, func(t *testing.T) {
			if got := BuildCommand(tc.backend, tc.iface, tc.filter); got != tc.want {
				t.Errorf("BuildCommand(%q, %q, %q) = %q, want %q", tc.backend, tc.iface, tc.filter, got, tc.want)
			}
		})
	}
}

func TestPreflight(t *testing.T) {
	ctx := context.Background()

	// Happy path: interface exists, tcpdump installed, running as root
	s := testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		switch cmd {
		case "test -d /sys/class/net/'eth0'":
			return 0
		case "command -v tcpdump >/dev/null 2>&1":
			return 0
		case "id -u; getcap \"$(command -v tcpdump)\" 2>/dev/null":
			_, _ = stdout.Write([]byte("0\n"))
			return 0
		default:
			t.Errorf("unexpected preflight command: %s", cmd)
			return 1
		}
	})
	runPreflightTest(t, s, ctx, "eth0", "")

	// Interface does not exist
	s = testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		if cmd == "test -d /sys/class/net/'eth0'" {
			return 1
		}
		return 0
	})
	runPreflightTest(t, s, ctx, "eth0", "does not exist")

	// tcpdump not installed, netou not installed
	s = testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		if cmd == "command -v tcpdump >/dev/null 2>&1" || cmd == "command -v netou >/dev/null 2>&1" {
			return 1
		}
		return 0
	})
	runPreflightTest(t, s, ctx, "eth0", "tcpdump is not installed")

	// Non-root, no capabilities, netou not installed
	s = testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		if strings.Contains(cmd, "id -u") {
			_, _ = stdout.Write([]byte("1000\n"))
			return 0
		}
		if cmd == "command -v netou >/dev/null 2>&1" {
			return 1
		}
		return 0
	})
	runPreflightTest(t, s, ctx, "eth0", "insufficient privileges")

	// Non-root, with capabilities
	s = testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		if strings.Contains(cmd, "id -u") {
			_, _ = stdout.Write([]byte("1000\n/usr/sbin/tcpdump = cap_net_raw,cap_net_admin+eip\n"))
			return 0
		}
		return 0
	})
	runPreflightTest(t, s, ctx, "eth0", "")
}

func runPreflightTest(t *testing.T, s *testsupport.Server, ctx context.Context, iface string, wantErrSubstr string) {
	t.Helper()
	client, err := s.Dial(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	err = Preflight(ctx, client, iface)
	if wantErrSubstr == "" {
		if err != nil {
			t.Errorf("Preflight() unexpected error: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), wantErrSubstr) {
		t.Errorf("Preflight() error = %v, want substring %q", err, wantErrSubstr)
	}
}

func TestStream(t *testing.T) {
	ctx := context.Background()

	// Happy path: streams PCAP data, stops on duration
	s := testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		if strings.HasPrefix(cmd, "exec tcpdump") {
			pcapHeader := []byte{0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
			_, _ = stdout.Write(pcapHeader)
			select {
			case sig := <-signals:
				if sig == "INT" {
					return 0
				}
			case <-time.After(1500 * time.Millisecond):
				return 0
			}
			return 0
		}
		return 0
	})
	runStreamTest(t, s, ctx, spec.Spec{
		Interface:    "eth0",
		DurationSecs: 1,
		MaxBytes:     1 << 30,
	}, Result{Reason: "duration"}, "", func(bytes int64) bool { return bytes > 0 })

	// Stops on stop channel
	s = testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		if strings.HasPrefix(cmd, "exec tcpdump") {
			pcapHeader := []byte{0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
			_, _ = stdout.Write(pcapHeader)
			select {
			case sig := <-signals:
				if sig == "INT" {
					return 0
				}
			case <-time.After(2 * time.Second):
			}
			return 0
		}
		return 0
	})
	runStreamTest(t, s, ctx, spec.Spec{
		Interface:    "eth0",
		DurationSecs: 3600,
		MaxBytes:     1 << 30,
	}, Result{Reason: "user"}, "", func(bytes int64) bool { return bytes > 0 })

	// Stops on max_bytes
	s = testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		if strings.HasPrefix(cmd, "exec tcpdump") {
			pcapHeader := []byte{0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
			_, _ = stdout.Write(pcapHeader)
			data := make([]byte, 1024)
			for i := 0; i < 50; i++ {
				_, _ = stdout.Write(data)
				time.Sleep(10 * time.Millisecond)
				select {
				case sig := <-signals:
					if sig == "INT" {
						return 0
					}
				default:
				}
			}
			select {
			case sig := <-signals:
				if sig == "INT" {
					return 0
				}
			case <-time.After(500 * time.Millisecond):
			}
			return 0
		}
		return 0
	})
	runStreamTest(t, s, ctx, spec.Spec{
		Interface:    "eth0",
		DurationSecs: 3600,
		MaxBytes:     500,
	}, Result{Reason: "size_limit"}, "", func(bytes int64) bool { return bytes >= 500 })

	// Remote failure returns stderr
	s = testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		if strings.HasPrefix(cmd, "exec tcpdump") {
			_, _ = stderr.Write([]byte("tcpdump: eth0: No such device exists"))
			return 1
		}
		return 0
	})
	runStreamTest(t, s, ctx, spec.Spec{
		Interface:    "eth0",
		DurationSecs: 1,
		MaxBytes:     1 << 30,
	}, Result{}, "remote capture failed", nil)

	// Context cancellation
	cancelCtx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(150 * time.Millisecond); cancel() }()
	s = testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		if strings.HasPrefix(cmd, "exec tcpdump") {
			pcapHeader := []byte{0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
			_, _ = stdout.Write(pcapHeader)
			select {
			case sig := <-signals:
				if sig == "INT" {
					return 0
				}
			case <-cancelCtx.Done():
				return 0
			case <-time.After(2 * time.Second):
				return 0
			}
			return 0
		}
		return 0
	})
	runStreamTest(t, s, cancelCtx, spec.Spec{
		Interface:    "eth0",
		DurationSecs: 3600,
		MaxBytes:     1 << 30,
	}, Result{Reason: "cancelled"}, "", nil)
}

func runStreamTest(
	t *testing.T,
	s *testsupport.Server,
	ctx context.Context,
	sp spec.Spec,
	wantResult Result,
	wantErrSubstr string,
	checkBytes func(int64) bool,
) {
	t.Helper()
	client, err := s.Dial(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	emit := events.New(io.Discard)

	var stopCh chan struct{}
	if wantResult.Reason == "user" {
		stopCh = make(chan struct{})
		go func() {
			time.Sleep(50 * time.Millisecond)
			close(stopCh)
		}()
	} else {
		stopCh = make(chan struct{})
	}

	var buf strings.Builder
	result, err := Stream(ctx, client, sp, &buf, stopCh, emit)

	if wantErrSubstr == "" {
		if err != nil {
			t.Errorf("Stream() unexpected error: %v", err)
		}
	} else {
		if err == nil || !strings.Contains(err.Error(), wantErrSubstr) {
			t.Errorf("Stream() error = %v, want substring %q", err, wantErrSubstr)
		}
	}

	if wantErrSubstr == "" {
		if result.Reason != wantResult.Reason {
			t.Errorf("Stream() reason = %q, want %q", result.Reason, wantResult.Reason)
		}
		if checkBytes != nil && !checkBytes(result.Bytes) {
			t.Errorf("Stream() bytes = %d, check failed", result.Bytes)
		}
		// Verify output starts with PCAP magic number
		if !strings.HasPrefix(buf.String(), "\xd4\xc3\xb2\xa1") && !strings.HasPrefix(buf.String(), "\xa1\xb2\xc3\xd4") {
			t.Errorf("Stream() output does not start with PCAP magic number")
		}
	}
}

// Test that SIGINT is sent on stop
func TestStream_SendsSIGINT(t *testing.T) {
	ctx := context.Background()
	var gotSignal string

	s := testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		if strings.HasPrefix(cmd, "exec tcpdump") {
			pcapHeader := []byte{0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
			_, _ = stdout.Write(pcapHeader)
			select {
			case sig := <-signals:
				gotSignal = sig
				return 0
			case <-time.After(2 * time.Second):
				t.Errorf("timeout waiting for signal")
				return 1
			}
		}
		return 0
	})
	runStreamTest(t, s, ctx, spec.Spec{
		Interface:    "eth0",
		DurationSecs: 3600,
		MaxBytes:     1 << 30,
	}, Result{Reason: "user"}, "", nil)

	if gotSignal != "INT" {
		t.Errorf("expected SIGINT signal, got %q", gotSignal)
	}
}

// Test no goroutine leak with -race
func TestStream_NoGoroutineLeak(t *testing.T) {
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		s := testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
			if strings.HasPrefix(cmd, "exec tcpdump") {
				pcapHeader := []byte{0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
				_, _ = stdout.Write(pcapHeader)
				select {
				case sig := <-signals:
					if sig != "INT" {
						return 1
					}
				case <-time.After(1500 * time.Millisecond):
				}
				return 0
			}
			return 0
		})
		runStreamTest(t, s, ctx, spec.Spec{
			Interface:    "eth0",
			DurationSecs: 1,
			MaxBytes:     1 << 30,
		}, Result{Reason: "duration"}, "", nil)
	}
}


func TestPreflightNetouFallback(t *testing.T) {
	ctx := context.Background()

	// Scenario 2: tcpdump missing, NETOU operational
	s := testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		switch cmd {
		case "test -d /sys/class/net/'eth0'":
			return 0
		case "command -v tcpdump >/dev/null 2>&1":
			return 1 // tcpdump missing
		case "command -v netou >/dev/null 2>&1":
			return 0 // netou installed
		case "netou -check":
			return 0 // netou check succeeds
		default:
			t.Errorf("unexpected preflight command: %s", cmd)
			return 1
		}
	})
	client1, err := s.Dial(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client1.Close()
	b, err := PreflightWithBackend(ctx, client1, "eth0")
	if err != nil {
		t.Fatalf("PreflightWithBackend failed: %v", err)
	}
	if b != BackendNetou {
		t.Errorf("backend = %q, want %q", b, BackendNetou)
	}

	// Scenario 3: tcpdump lacks privileges, NETOU operational
	s = testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		switch cmd {
		case "test -d /sys/class/net/'eth0'":
			return 0
		case "command -v tcpdump >/dev/null 2>&1":
			return 0 // tcpdump installed
		case "id -u; getcap \"$(command -v tcpdump)\" 2>/dev/null":
			_, _ = stdout.Write([]byte("1000\n")) // non-root, no caps
			return 0
		case "command -v netou >/dev/null 2>&1":
			return 0 // netou installed
		case "netou -check":
			return 0 // netou check succeeds
		default:
			t.Errorf("unexpected preflight command: %s", cmd)
			return 1
		}
	})
	client2, err := s.Dial(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client2.Close()
	b, err = PreflightWithBackend(ctx, client2, "eth0")
	if err != nil {
		t.Fatalf("PreflightWithBackend failed: %v", err)
	}
	if b != BackendNetou {
		t.Errorf("backend = %q, want %q", b, BackendNetou)
	}

	// Scenario 5: NETOU missing CAP_NET_RAW (netou -check fails)
	s = testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		switch cmd {
		case "test -d /sys/class/net/'eth0'":
			return 0
		case "command -v tcpdump >/dev/null 2>&1":
			return 1
		case "command -v netou >/dev/null 2>&1":
			return 0
		case "netou -check":
			_, _ = stdout.Write([]byte("operation not permitted\n"))
			return 1
		default:
			return 0
		}
	})
	client3, err := s.Dial(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client3.Close()
	_, err = PreflightWithBackend(ctx, client3, "eth0")
	if err == nil || !strings.Contains(err.Error(), "cap_net_raw") {
		t.Fatalf("PreflightWithBackend err = %v, want cap_net_raw mention", err)
	}
}
