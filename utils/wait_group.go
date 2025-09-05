package utils

import (
	"context"
	"sync"
	"sync/atomic"
)

// WaitGroup is like WaitGroup but can be canceled via context.
type WaitGroup struct {
	ch     chan struct{} // signals task completion
	count  atomic.Int32  // number of active tasks
	once   sync.Once
	closed atomic.Bool // prevents double close of ch
}

// this method help us to avoid introduce explicit constructor
func (g *WaitGroup) ensureInited() {
	g.once.Do(func() {
		g.ch = make(chan struct{}, 1)
	})
}

// Add increases the counter.
func (g *WaitGroup) Add(delta int) {
	g.ensureInited()
	g.count.Add(int32(delta))
}

// Done decreases the counter.
func (g *WaitGroup) Done() {
	g.ensureInited()
	if g.count.Add(-1) == 0 && g.closed.CompareAndSwap(false, true) {
		close(g.ch)
	}
}

// Wait waits until all tasks are done or the context is canceled.
// Returns ctx.Err() if canceled, nil if all tasks finished.
func (g *WaitGroup) Wait(ctx context.Context) error {
	g.ensureInited()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-g.ch:
		return nil
	}
}
