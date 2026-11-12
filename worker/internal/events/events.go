// Package events writes machine-readable progress/diagnostic events as JSON lines.
// They go to stderr; stdout is reserved for the raw PCAP stream and must never carry text.
package events

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Emitter is safe for concurrent use.
type Emitter struct {
	mu sync.Mutex
	w  io.Writer
}

func New(w io.Writer) *Emitter { return &Emitter{w: w} }

// Emit writes one event. Errors writing diagnostics are deliberately ignored.
func (e *Emitter) Emit(event string, fields map[string]any) {
	m := map[string]any{"event": event, "ts": time.Now().UTC().Format(time.RFC3339Nano)}
	for k, v := range fields {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, _ = e.w.Write(append(b, '\n'))
}
