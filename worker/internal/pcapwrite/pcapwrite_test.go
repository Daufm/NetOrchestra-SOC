package pcapwrite_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"netorchestra/worker/internal/pcapwrite"
)

func TestPcapWriterHeader(t *testing.T) {
	var buf bytes.Buffer
	snaplen := uint32(65535)
	pw, err := pcapwrite.New(&buf, snaplen)
	if err != nil {
		t.Fatalf("pcapwrite.New() err = %v", err)
	}

	if buf.Len() != 24 {
		t.Fatalf("pcap global header len = %d, want 24", buf.Len())
	}

	magic := binary.LittleEndian.Uint32(buf.Bytes()[0:4])
	if magic != pcapwrite.MagicMicroseconds {
		t.Fatalf("magic = 0x%x, want 0x%x", magic, pcapwrite.MagicMicroseconds)
	}

	// Write a packet
	pktData := []byte("hello ethernet frame packet")
	now := time.Unix(1700000000, 500000000)
	err = pw.WritePacket(now, uint32(len(pktData)), pktData)
	if err != nil {
		t.Fatalf("WritePacket err = %v", err)
	}

	// 24 + 16 + len(pktData)
	expectedLen := 24 + 16 + len(pktData)
	if buf.Len() != expectedLen {
		t.Fatalf("total len = %d, want %d", buf.Len(), expectedLen)
	}

	pktHdr := buf.Bytes()[24:40]
	sec := binary.LittleEndian.Uint32(pktHdr[0:4])
	usec := binary.LittleEndian.Uint32(pktHdr[4:8])
	capLen := binary.LittleEndian.Uint32(pktHdr[8:12])
	origLen := binary.LittleEndian.Uint32(pktHdr[12:16])

	if sec != 1700000000 || usec != 500000 {
		t.Errorf("timestamp = %d.%d, want 1700000000.500000", sec, usec)
	}
	if capLen != uint32(len(pktData)) || origLen != uint32(len(pktData)) {
		t.Errorf("lengths cap=%d orig=%d, want %d", capLen, origLen, len(pktData))
	}
}

func TestTsharkCompatible(t *testing.T) {
	var buf bytes.Buffer
	pw, err := pcapwrite.New(&buf, 65535)
	if err != nil {
		t.Fatal(err)
	}
	frame := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x01, 0x79, 0xc6, // ICMP with valid checksum
		192, 168, 1, 10,
		192, 168, 1, 20,
		0x08, 0x00, 0xf7, 0xff,
		0x00, 0x01, 0x00, 0x01,
	}
	now := time.Unix(1700000000, 0)
	if err := pw.WritePacket(now, uint32(len(frame)), frame); err != nil {
		t.Fatal(err)
	}

	f, err := os.CreateTemp("", "test_netou_*.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	f.Close()

	cmd := exec.Command("tshark", "-r", f.Name(), "-T", "fields", "-e", "ip.src", "-e", "ip.dst")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tshark failed: %v, output: %s", err, string(out))
	}
	if !strings.Contains(string(out), "192.168.1.10\t192.168.1.20") {
		t.Fatalf("unexpected tshark output: %s", string(out))
	}
}
