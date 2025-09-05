package utils

import (
	"context"
	"time"
)

// Sleep pauses the current goroutine for the specified duration or until the context is cancelled.
// It returns nil if the sleep completed normally, or the context error if the context was cancelled
// before the sleep duration elapsed. This function is useful for implementing cancellable delays in
// long-running operations that need to respect context cancellation.
//
// Parameters:
//   - ctx: The context that can be used to cancel the sleep operation
//   - amount: The duration to sleep for
//
// Returns:
//   - error: nil if sleep completed normally, context error if cancelled
func Sleep(ctx context.Context, amount time.Duration) error {
	select {
	case <-time.After(amount):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
