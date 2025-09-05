package utils

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWaitGroup_AllDone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var g WaitGroup

	for range 1000 {
		g.Add(1)
		go func() {
			time.Sleep(time.Millisecond) // simulate work
			g.Done()
		}()
	}

	assert.NoError(t, g.Wait(ctx))
}

func TestWaitGroup_Cancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	var g WaitGroup

	for range 100 {
		g.Add(1)
		go func() {
			time.Sleep(time.Second) // long work
			g.Done()
		}()
	}

	assert.Error(t, g.Wait(ctx), context.Canceled)
}

func TestWaitGroup_RaceAddDone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var g WaitGroup
	var wg sync.WaitGroup

	for range 1000 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.Add(1)
			time.Sleep(time.Microsecond)
			g.Done()
		}()
	}

	wg.Wait()
	if err := g.Wait(ctx); err != nil {
		t.Fatalf("expected all done, got error: %v", err)
	}
}

func TestWaitGroup_ParallelWaiters(t *testing.T) {
	var g WaitGroup

	// Add tasks
	for range 100 {
		g.Add(1)
		go func() {
			time.Sleep(time.Millisecond)
			g.Done()
		}()
	}

	// Spin up many waiters in parallel
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			assert.NoError(t, g.Wait(ctx))
		}()
	}

	wg.Wait()
}

func TestWaitGroup_IncorrectSequence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var g WaitGroup

	go func() {
		time.Sleep(10 * time.Millisecond)
		g.Add(1)
		time.Sleep(10 * time.Millisecond)
		g.Done()
	}()

	// starts before actual Add() method is called
	assert.NoError(t, g.Wait(ctx))
}
