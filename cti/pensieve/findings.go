package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

func strInput(inputs map[string]any, key string) string {
	v, _ := inputs[key].(string)
	return strings.TrimSpace(v)
}

func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return fmt.Sprintf("%x", h[:8])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

type emitter struct {
	out     chan<- connector.Finding
	ctx     context.Context
	max     int
	sent    int
	stopped bool
}

func newEmitter(ctx context.Context, out chan<- connector.Finding, max int) *emitter {
	return &emitter{out: out, ctx: ctx, max: max}
}

func (e *emitter) emit(f connector.Finding) bool {
	if e.stopped {
		return false
	}
	if e.max > 0 && e.sent >= e.max {
		e.stopped = true
		return false
	}
	select {
	case e.out <- f:
		e.sent++
		return true
	case <-e.ctx.Done():
		e.stopped = true
		return false
	}
}
