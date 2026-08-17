package utils

import (
	"sync"
	"time"
)

type loaderFunc[K comparable, V any] func(key K) (V, time.Time, error)

type cacheEntity[V any] struct {
	value V
	exp   time.Time
}

// LoadingCache is a generic TTL cache: RLock on hit, exclusive Lock only when loading.
type LoadingCache[K comparable, V any] struct {
	mu     sync.RWMutex
	loader loaderFunc[K, V]
	data   map[K]cacheEntity[V]
}

func NewLoadingCache[K comparable, V any](loader loaderFunc[K, V]) *LoadingCache[K, V] {
	return &LoadingCache[K, V]{
		loader: loader,
		data:   make(map[K]cacheEntity[V]),
	}
}

func (c *LoadingCache[K, V]) Get(key K) (V, error) {
	var zero V

	c.mu.RLock()
	ent, ok := c.data[key]
	c.mu.RUnlock()
	if ok && ent.exp.After(time.Now()) {
		return ent.value, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if ent, ok = c.data[key]; ok && ent.exp.After(time.Now()) {
		return ent.value, nil
	}

	value, exp, err := c.loader(key)
	if err != nil {
		return zero, err
	}
	c.data[key] = cacheEntity[V]{value: value, exp: exp}
	return value, nil
}
