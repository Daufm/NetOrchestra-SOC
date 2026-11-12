// Package pcapwrite provides a minimal, dependency-free writer for standard PCAP files (format 2.4).
package pcapwrite

import (
	"encoding/binary"
	"io"
	"time"
)

const (
	// MagicMicroseconds is the standard PCAP magic number (microseconds precision).
	MagicMicroseconds = 0xa1b2c3d4
	MajorVersion      = 2
	MinorVersion      = 4
	LinkTypeEthernet  = 1 // DLT_EN10MB
)

// Writer writes PCAP global and packet headers to an output stream.
type Writer struct {
	w io.Writer
}

// New creates a Writer and writes the standard 24-byte PCAP file header.
func New(w io.Writer, snaplen uint32) (*Writer, error) {
	// PCAP Global Header: 24 bytes
	//   magic (4B), v_major (2B), v_minor (2B), thiszone (4B), sigfigs (4B), snaplen (4B), network (4B)
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], MagicMicroseconds)
	binary.LittleEndian.PutUint16(hdr[4:6], MajorVersion)
	binary.LittleEndian.PutUint16(hdr[6:8], MinorVersion)
	binary.LittleEndian.PutUint32(hdr[8:12], 0) // GMT to local correction
	binary.LittleEndian.PutUint32(hdr[12:16], 0) // accuracy of timestamps
	binary.LittleEndian.PutUint32(hdr[16:20], snaplen)
	binary.LittleEndian.PutUint32(hdr[20:24], LinkTypeEthernet)

	if _, err := w.Write(hdr[:]); err != nil {
		return nil, err
	}
	return &Writer{w: w}, nil
}

// WritePacket writes a single packet record with its 16-byte PCAP packet header.
func (pw *Writer) WritePacket(t time.Time, origLen uint32, data []byte) error {
	var hdr [16]byte
	sec := uint32(t.Unix())
	usec := uint32(t.Nanosecond() / 1000)
	capLen := uint32(len(data))

	binary.LittleEndian.PutUint32(hdr[0:4], sec)
	binary.LittleEndian.PutUint32(hdr[4:8], usec)
	binary.LittleEndian.PutUint32(hdr[8:12], capLen)
	binary.LittleEndian.PutUint32(hdr[12:16], origLen)

	if _, err := pw.w.Write(hdr[:]); err != nil {
		return err
	}
	if capLen > 0 {
		if _, err := pw.w.Write(data); err != nil {
			return err
		}
	}
	return nil
}
