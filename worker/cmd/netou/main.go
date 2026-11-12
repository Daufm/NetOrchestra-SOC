// Command netou is a standalone, lightweight Linux AF_PACKET capture helper.
// It outputs standard PCAP 2.4 binary stream to stdout and diagnostics to stderr.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"netorchestra/worker/internal/pcapwrite"
)

func htons(i uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

type sockFprog struct {
	Len    uint16
	Filter *syscall.SockFilter
}

// parseBPFInstructions parses raw BPF bytecode instructions formatted as:
// "<code1> <jt1> <jf1> <k1>\n<code2> <jt2> <jf2> <k2>\n..."
func parseBPFInstructions(raw string) ([]syscall.SockFilter, error) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	var filters []syscall.SockFilter
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 4 {
			return nil, fmt.Errorf("line %d: expected 4 integers (code jt jf k), got %d", i+1, len(parts))
		}
		code, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("line %d invalid code: %w", i+1, err)
		}
		jt, err := strconv.ParseUint(parts[1], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("line %d invalid jt: %w", i+1, err)
		}
		jf, err := strconv.ParseUint(parts[2], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("line %d invalid jf: %w", i+1, err)
		}
		k, err := strconv.ParseUint(parts[3], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("line %d invalid k: %w", i+1, err)
		}
		filters = append(filters, syscall.SockFilter{
			Code: uint16(code),
			Jt:   uint8(jt),
			Jf:   uint8(jf),
			K:    uint32(k),
		})
	}
	return filters, nil
}

func attachBPF(fd int, filters []syscall.SockFilter) error {
	if len(filters) == 0 {
		return nil
	}
	if len(filters) > 65535 {
		return fmt.Errorf("too many BPF filter instructions: %d", len(filters))
	}
	fprog := sockFprog{
		Len:    uint16(len(filters)),
		Filter: &filters[0],
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_SOCKET),
		uintptr(syscall.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&fprog)),
		unsafe.Sizeof(fprog),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func main() {
	var (
		ifaceName string
		snaplen   int
		duration  int
		bpfRaw    string
		checkOnly bool
	)

	flag.StringVar(&ifaceName, "i", "", "Interface to capture on (e.g. eth0, any)")
	flag.IntVar(&snaplen, "s", 65535, "Snapshot length (0 means 65535)")
	flag.IntVar(&duration, "d", 0, "Capture duration in seconds (0 for unlimited)")
	flag.StringVar(&bpfRaw, "bpf-raw", "", "Raw BPF bytecode instructions (newline-separated)")
	flag.BoolVar(&checkOnly, "check", false, "Test socket creation and permissions then exit")
	flag.Parse()

	if snaplen <= 0 || snaplen > 65535 {
		snaplen = 65535
	}

	if checkOnly {
		// Just verify AF_PACKET socket can be opened on Linux
		proto := htons(uint16(syscall.ETH_P_ALL))
		fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(proto))
		if err != nil {
			fmt.Fprintf(os.Stderr, "netou permission check failed: %v\n", err)
			os.Exit(1)
		}
		_ = syscall.Close(fd)
		fmt.Fprintln(os.Stderr, "netou operational (CAP_NET_RAW verified)")
		os.Exit(0)
	}

	if ifaceName == "" {
		fmt.Fprintln(os.Stderr, "netou: -i <interface> is required")
		os.Exit(1)
	}

	// Resolve interface index
	var ifIndex int
	if ifaceName != "any" {
		ifi, err := net.InterfaceByName(ifaceName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "netou: invalid interface %q: %v\n", ifaceName, err)
			os.Exit(1)
		}
		ifIndex = ifi.Index
	}

	// Open raw AF_PACKET socket
	proto := htons(uint16(syscall.ETH_P_ALL))
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(proto))
	if err != nil {
		fmt.Fprintf(os.Stderr, "netou: cannot open AF_PACKET socket: %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(fd)

	// Bind to specified interface if not "any"
	if ifIndex != 0 {
		var sa syscall.SockaddrLinklayer
		sa.Protocol = proto
		sa.Ifindex = ifIndex
		if err := syscall.Bind(fd, &sa); err != nil {
			fmt.Fprintf(os.Stderr, "netou: cannot bind to interface %q: %v\n", ifaceName, err)
			os.Exit(1)
		}
	}

	// Attach BPF filter if provided
	if bpfRaw != "" {
		filters, err := parseBPFInstructions(bpfRaw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "netou: invalid BPF instructions: %v\n", err)
			os.Exit(1)
		}
		if err := attachBPF(fd, filters); err != nil {
			fmt.Fprintf(os.Stderr, "netou: cannot attach BPF filter: %v\n", err)
			os.Exit(1)
		}
	}

	// Write standard PCAP global header to stdout
	pw, err := pcapwrite.New(os.Stdout, uint32(snaplen))
	if err != nil {
		fmt.Fprintf(os.Stderr, "netou: failed to write PCAP header: %v\n", err)
		os.Exit(1)
	}

	// Setup signal and duration handling
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(duration)*time.Second)
		defer cancel()
	}

	fmt.Fprintf(os.Stderr, "netou: capturing on %s (snaplen %d)\n", ifaceName, snaplen)

	// Capture loop
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "netou: capture stopped")
			return
		default:
		}

		// Read packet
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR || err == syscall.EAGAIN {
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				fmt.Fprintf(os.Stderr, "netou: recvfrom error: %v\n", err)
				os.Exit(1)
			}
		}

		now := time.Now()
		origLen := uint32(n)
		capData := buf[:n]
		if len(capData) > snaplen {
			capData = capData[:snaplen]
		}

		if err := pw.WritePacket(now, origLen, capData); err != nil {
			// If stdout pipe is broken (e.g. backend closed connection)
			fmt.Fprintf(os.Stderr, "netou: stdout write error: %v\n", err)
			return
		}
	}
}
