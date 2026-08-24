package utils

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadingCacheGetLoadsAndHits(t *testing.T) {
	var loads atomic.Int32
	c := NewLoadingCache(func(_ context.Context, key string) (string, time.Time, error) {
		loads.Add(1)
		return "value-" + key, time.Now().Add(time.Hour), nil
	})

	got, err := c.Get(t.Context(), "a")
	require.NoError(t, err)
	assert.Equal(t, "value-a", got)

	got, err = c.Get(t.Context(), "a")
	require.NoError(t, err)
	assert.Equal(t, "value-a", got)
	assert.Equal(t, int32(1), loads.Load())
}

func TestLoadingCacheGetReloadsExpired(t *testing.T) {
	var loads atomic.Int32
	c := NewLoadingCache(func(_ context.Context, _ string) (string, time.Time, error) {
		n := loads.Add(1)
		return fmt.Sprintf("value-%d", n), time.Now().Add(-time.Second), nil
	})

	got, err := c.Get(t.Context(), "a")
	require.NoError(t, err)
	assert.Equal(t, "value-1", got)

	got, err = c.Get(t.Context(), "a")
	require.NoError(t, err)
	assert.Equal(t, "value-2", got)
	assert.Equal(t, int32(2), loads.Load())
}

func TestLoadingCacheGetDoesNotStoreOnError(t *testing.T) {
	var loads atomic.Int32
	c := NewLoadingCache(func(_ context.Context, _ string) (string, time.Time, error) {
		loads.Add(1)
		return "", time.Time{}, fmt.Errorf("boom")
	})

	_, err := c.Get(t.Context(), "a")
	require.Error(t, err)
	_, err = c.Get(t.Context(), "a")
	require.Error(t, err)
	assert.Equal(t, int32(2), loads.Load())
}

func TestLoadingCacheGetConcurrentMissLoadsOnce(t *testing.T) {
	var loads atomic.Int32
	c := NewLoadingCache(func(_ context.Context, key string) (string, time.Time, error) {
		loads.Add(1)
		time.Sleep(50 * time.Millisecond)
		return "value-" + key, time.Now().Add(time.Hour), nil
	})

	const goroutines = 16
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			got, err := c.Get(t.Context(), "a")
			if err != nil {
				errCh <- err
				return
			}
			if got != "value-a" {
				errCh <- fmt.Errorf("unexpected value %q", got)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), loads.Load())
}
