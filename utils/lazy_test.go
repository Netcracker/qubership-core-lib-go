package utils

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLazy_Get_Success(t *testing.T) {
	execCounter := atomic.Int32{}
	initializer := func() (int, error) {
		execCounter.Add(1)
		return int(execCounter.Load()), nil
	}

	lazy := NewLazy(initializer)

	// First call should initialize and return the value
	value, err := lazy.Get()
	assert.NoError(t, err)
	assert.Equal(t, 1, value)

	// Second call should return the same value without calling initializer
	value2, err2 := lazy.Get()
	assert.NoError(t, err2)
	assert.Equal(t, 1, value2)

}

func TestLazy_Get_Concurrent(t *testing.T) {
	execCounter := atomic.Int32{}
	initializer := func() (int, error) {
		execCounter.Add(1)
		return int(execCounter.Load()), nil
	}

	lazy := NewLazy(initializer)
	var wg sync.WaitGroup
	// Launch multiple goroutines that call Get() concurrently
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, err := lazy.Get()
			assert.NoError(t, err)
			assert.Equal(t, 1, value)
		}()
	}

	wg.Wait()
}

func TestLazy_Get_Retry(t *testing.T) {
	execCounter := atomic.Int32{}
	initializer := func() (int, error) {
		execCounter.Add(1)
		if execCounter.Load() < 2 {
			return 0, fmt.Errorf("retry")
		}
		return int(execCounter.Load()), nil
	}

	lazy := NewLazy(initializer)

	_, err := lazy.Get()
	assert.Error(t, err)

	{
		value, err := lazy.Get()
		assert.NoError(t, err)
		assert.Equal(t, 2, value)
	}

	{
		value, err := lazy.Get()
		assert.NoError(t, err)
		assert.Equal(t, 2, value)
	}
}
