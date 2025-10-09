// Package utils provides utility functions and types for common operations.
package utils

import "sync"

// Lazy provides thread-safe lazy initialization with error handling and retry capability.
// Unlike sync.Once, Lazy allows reinitialization when the initializer function returns an error.
//
// Key differences from sync.Once:
//   - sync.Once only executes the function once, regardless of success or failure
//   - Lazy retries initialization on error, allowing for transient failure recovery
//   - sync.Once has no return value; Lazy returns both value and error
//   - Lazy provides generic type safety with Go generics
//
// Use cases:
//   - Initializing resources that may fail temporarily (network connections, file operations)
//   - Caching expensive computations that might fail due to external dependencies
//   - Implementing retry logic for critical initialization steps
//
// Thread safety:
//   - All methods are safe for concurrent use
//   - Multiple goroutines calling Get() will block until initialization completes
//   - Only one goroutine will execute the initializer function
//
// Error handling:
//   - If initializer returns an error, the Lazy remains uninitialized
//   - Subsequent calls to Get() will retry the initialization
//   - Once initialization succeeds, the value is cached and errors are not retried
type Lazy[T any] struct {
	mu          sync.Mutex
	initialized bool
	initializer func() (T, error)
	value       T
}

// NewLazy creates a new Lazy instance with the provided initializer function.
// The initializer function will be called on the first successful call to Get().
// If the initializer returns an error, it will be retried on subsequent Get() calls.
//
// Example:
//
//	lazy := NewLazy(func() (string, error) {
//	    return expensiveOperation()
//	})
func NewLazy[T any](initializer func() (T, error)) *Lazy[T] {
	return &Lazy[T]{
		initialized: false,
		initializer: initializer,
	}
}

// Get returns the lazily initialized value, initializing it if necessary.
//
// Behavior:
//   - If already initialized successfully, returns the cached value immediately
//   - If not initialized, calls the initializer function under a mutex lock
//   - If initialization fails, returns the zero value and the error
//   - If initialization succeeds, caches the value and returns it
//   - Subsequent calls return the cached value without re-executing the initializer
//
// Thread safety:
//   - Safe for concurrent use from multiple goroutines
//   - Only one goroutine will execute the initializer function
//   - Other goroutines will block until initialization completes
//
// Error handling:
//   - Returns the zero value of type T and the error if initialization fails
//   - The Lazy remains uninitialized on error, allowing retry on next Get() call
//   - Once successful, the value is cached and future calls won't retry
//
// Example:
//
//	value, err := lazy.Get()
//	if err != nil {
//	    // Handle initialization error, can retry later
//	    return err
//	}
//	// Use value safely
func (l *Lazy[T]) Get() (T, error) {
	if l.initialized {
		return l.value, nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.initialized {
		return l.value, nil
	}

	v, err := l.initializer()
	if err != nil {
		return l.value, err
	}
	l.initialized = true
	l.value = v
	return l.value, nil
}
