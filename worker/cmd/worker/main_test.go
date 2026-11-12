package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"netorchestra/worker/internal/testsupport"
)

func TestRunRejectsInvalidSpec(t *testing.T) {
	var stdout, stderr bytes.Buffer
	env := func(key string) (string, bool) { return "", false }

	if code := run(context.Background(), strings.NewReader(`{"job_id":"bad"}`+"\n"), &stdout, &stderr, env); code != 2 {
		t.Fatalf("run() exit code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("invalid spec wrote %d bytes to stdout", stdout.Len())
	}
	assertEvent(t, stderr.Bytes(), "error")
}

func TestRunStreamsCaptureAndCleansUp(t *testing.T) {
	const payload = "\xd4\xc3\xb2\xa1\x02\x00\x04\x00"
	server := testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		switch cmd {
		case "test -d /sys/class/net/'eth0'":
			return 0
		case "command -v tcpdump >/dev/null 2>&1":
			return 0
		case "id -u; getcap \"$(command -v tcpdump)\" 2>/dev/null":
			_, _ = io.WriteString(stdout, "0\n")
			return 0
		}
		if strings.HasPrefix(cmd, "exec tcpdump") {
			_, _ = io.WriteString(stdout, payload)
			<-signals
			return 0
		}
		t.Errorf("unexpected command: %s", cmd)
		return 1
	})

	spec := map[string]any{
		"job_id": "0b6e5a1c-1111-4222-8333-444455556666",
		"host":   server.Host, "port": server.PortInt(), "username": "testuser",
		"credential_ref": server.Ref, "interface": "eth0", "duration_secs": 30,
		"filter": "", "max_bytes": 1 << 20,
	}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	env := func(key string) (string, bool) {
		switch key {
		case "NETO_WORKER_KEYS_DIR":
			return server.KeysDir, true
		case "NETO_WORKER_KNOWN_HOSTS":
			return server.KnownHosts, true
		case "NETO_SSH_DIAL_TIMEOUT":
			return "2s", true
		default:
			return "", false
		}
	}

	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run(context.Background(), pr, &stdout, &stderr, env)
	}()
	_, _ = pw.Write(append(specJSON, '\n'))
	time.Sleep(100 * time.Millisecond)
	_, _ = pw.Write([]byte("{\"cmd\":\"stop\"}\n"))
	_ = pw.Close()

	if code := <-done; code != 0 {
		t.Fatalf("run() exit code = %d; stderr=%s", code, stderr.String())
	}
	if got := stdout.String(); got != payload {
		t.Fatalf("stdout = %q, want %q", got, payload)
	}
	events := parseEvents(t, stderr.Bytes())
	if !hasEvent(events, "started") || !hasEvent(events, "stopped") || !hasEvent(events, "cleanup") {
		t.Fatalf("events missing lifecycle entries: %v", events)
	}
	if countEvents(events, "cleanup") != 1 {
		t.Fatalf("cleanup event count = %d, want 1", countEvents(events, "cleanup"))
	}
}

func parseEvents(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	var events []map[string]any
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("invalid stderr event %q: %v", scanner.Text(), err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

func assertEvent(t *testing.T, data []byte, want string) {
	t.Helper()
	if !hasEvent(parseEvents(t, data), want) {
		t.Fatalf("event %q not found in %q", want, data)
	}
}

func hasEvent(events []map[string]any, want string) bool {
	return countEvents(events, want) > 0
}

func countEvents(events []map[string]any, want string) int {
	var count int
	for _, event := range events {
		if event["event"] == want {
			count++
		}
	}
	return count
}


func TestRunStreamsCaptureNetouFallback(t *testing.T) {
	const payload = "\xd4\xc3\xb2\xa1\x02\x00\x04\x00"
	server := testsupport.Start(t, func(cmd string, stdout, stderr io.Writer, signals <-chan string) uint32 {
		switch cmd {
		case "test -d /sys/class/net/'eth0'":
			return 0
		case "command -v tcpdump >/dev/null 2>&1":
			return 1 // tcpdump missing
		case "command -v netou >/dev/null 2>&1":
			return 0 // netou present
		case "netou -check":
			return 0 // netou check ok
		}
		if strings.HasPrefix(cmd, "exec netou") {
			_, _ = io.WriteString(stdout, payload)
			<-signals
			return 0
		}
		t.Errorf("unexpected command: %s", cmd)
		return 1
	})

	spec := map[string]any{
		"job_id": "0b6e5a1c-1111-4222-8333-444455556667",
		"host":   server.Host, "port": server.PortInt(), "username": "testuser",
		"credential_ref": server.Ref, "interface": "eth0", "duration_secs": 30,
		"filter": "", "max_bytes": 1 << 20,
	}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	env := func(key string) (string, bool) {
		switch key {
		case "NETO_WORKER_KEYS_DIR":
			return server.KeysDir, true
		case "NETO_WORKER_KNOWN_HOSTS":
			return server.KnownHosts, true
		case "NETO_SSH_DIAL_TIMEOUT":
			return "2s", true
		default:
			return "", false
		}
	}

	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run(context.Background(), pr, &stdout, &stderr, env)
	}()
	_, _ = pw.Write(append(specJSON, '\n'))
	time.Sleep(100 * time.Millisecond)
	_, _ = pw.Write([]byte("{\"cmd\":\"stop\"}\n"))
	_ = pw.Close()

	if code := <-done; code != 0 {
		t.Fatalf("run() exit code = %d; stderr=%s", code, stderr.String())
	}
	if got := stdout.String(); got != payload {
		t.Fatalf("stdout = %q, want %q", got, payload)
	}
	events := parseEvents(t, stderr.Bytes())
	if !hasEvent(events, "started") || !hasEvent(events, "stopped") || !hasEvent(events, "cleanup") {
		t.Fatalf("events missing lifecycle entries: %v", events)
	}
	// Check that started event reports backend = NETOU (AF_PACKET)
	for _, ev := range events {
		if ev["event"] == "started" {
			if ev["backend"] != "NETOU (AF_PACKET)" {
				t.Errorf("started event backend = %v, want 'NETOU (AF_PACKET)'", ev["backend"])
			}
		}
	}
}
