package utils

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSleepNormalCompletion(t *testing.T) {
	ctx := context.Background()
	duration := 10 * time.Millisecond

	start := time.Now()
	err := Sleep(ctx, duration)
	elapsed := time.Since(start)

	assert.NoError(t, err, "Sleep should complete normally without error")
	assert.GreaterOrEqual(t, elapsed, duration, "Sleep should take at least the specified duration")
}

func TestSleepCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately
	duration := 100 * time.Millisecond

	start := time.Now()
	err := Sleep(ctx, duration)
	elapsed := time.Since(start)

	assert.Error(t, err, "Sleep should return error when context is already cancelled")
	assert.Equal(t, context.Canceled, err, "Sleep should return context.Canceled when context is already cancelled")
	assert.Less(t, elapsed, duration, "Sleep should complete quickly when context is cancelled")
}

func TestSleepContextCancelledDuringSleep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()
	duration := 50 * time.Millisecond

	start := time.Now()
	err := Sleep(ctx, duration)
	elapsed := time.Since(start)

	assert.Error(t, err, "Sleep should return error when context is cancelled during sleep")
	assert.Equal(t, context.Canceled, err, "Sleep should return context.Canceled when context is cancelled during sleep")
	assert.Less(t, elapsed, duration, "Sleep should complete quickly when context is cancelled")
}

func TestSleepContextTimeoutShorterThanSleep(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	duration := 50 * time.Millisecond

	start := time.Now()
	err := Sleep(ctx, duration)
	elapsed := time.Since(start)

	assert.Error(t, err, "Sleep should return error when context timeout is shorter than sleep duration")
	assert.Equal(t, context.DeadlineExceeded, err, "Sleep should return context.DeadlineExceeded when context timeout is shorter than sleep duration")
	assert.Less(t, elapsed, duration, "Sleep should complete quickly when context times out")
}

func TestSleepWithDeadline(t *testing.T) {
	// Test with context that has a deadline
	deadline := time.Now().Add(15 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	start := time.Now()
	err := Sleep(ctx, 50*time.Millisecond)
	elapsed := time.Since(start)

	assert.Error(t, err, "Sleep should return error when context has deadline")
	assert.Equal(t, context.DeadlineExceeded, err, "Sleep should return context.DeadlineExceeded when context has deadline")

	// Should complete around the deadline time
	expectedMin := 10 * time.Millisecond
	expectedMax := 25 * time.Millisecond
	assert.GreaterOrEqual(t, elapsed, expectedMin, "Sleep with deadline should take at least the minimum expected time")
	assert.LessOrEqual(t, elapsed, expectedMax, "Sleep with deadline should complete within the maximum expected time")
}
