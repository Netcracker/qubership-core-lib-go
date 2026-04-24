package tokensource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
)

func TestRefreshAudienceTokensCache_MixedDirectories(t *testing.T) {
	resetTokenSourceState(t)
	storage, err := newAudienceTokensStorage(t.TempDir())
	assert.NoError(t, err)
	defer func() {
			resetTokenSourceState(t)
		_ = storage.clear()
	}()

	err = storage.saveTokenValue(AudienceNetcracker, "netcracker-token")
	assert.NoError(t, err)

	err = os.MkdirAll(filepath.Join(storage.audienceTokensDir, "broken"), 0o775)
	assert.NoError(t, err)

	provider := DefaultTokenFileProvider{}
	err = provider.refreshAudienceTokensCache(storage.audienceTokensDir)
	assert.NoError(t, err)

	foundValidToken := false
	audienceTokensCache.Range(func(_, value any) bool {
		if result, ok := value.(tokenUpdateResult); ok && result.value == "netcracker-token" && result.err == nil {
			foundValidToken = true
			return false
		}
		return true
	})
	assert.True(t, foundValidToken)

	cachedBrokenToken, ok := audienceTokensCache.Load(TokenAudience("broken"))
	assert.True(t, ok)
	assert.Empty(t, cachedBrokenToken.(tokenUpdateResult).value)
	assert.ErrorContains(t, cachedBrokenToken.(tokenUpdateResult).err, "failed to read token at path")
}

func TestGetAudienceToken_RecreatesWatcherAfterContextDone(t *testing.T) {
	beforeEach(t)
	defer afterEach(t)

	err := audTokensStorage.saveTokenValue(AudienceNetcracker, "value")
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	token, err := GetAudienceToken(ctx, AudienceNetcracker)
	assert.NoError(t, err)
	assert.Equal(t, "value", token)
	cancel()

	assert.Eventually(t, func() bool {
		return audienceTokensWatcher.Load() == nil
	}, time.Second, time.Millisecond*20)

	ctx = t.Context()
	token, err = GetAudienceToken(ctx, AudienceNetcracker)
	assert.NoError(t, err)
	assert.Equal(t, "value", token)
}

func TestTokenWatcherListenFs_IgnoresNonDataEvents(t *testing.T) {
	watcher, err := fsnotify.NewWatcher()
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var updateCalls atomic.Int32
	var onCloseCalls atomic.Int32
	tw := &tokenWatcher{
		watcher: watcher,
		updateCache: func(string) error {
			updateCalls.Add(1)
			return nil
		},
		onClose: func() {
			onCloseCalls.Add(1)
		},
	}
	events := make(chan fsnotify.Event)
	errs := make(chan error)
	done := make(chan struct{})
	go func() {
		tw.listenFs(ctx, events, errs)
		close(done)
	}()

	events <- fsnotify.Event{Name: "token", Op: fsnotify.Write}
	cancel()
	<-done
	assert.Equal(t, int32(0), updateCalls.Load())
	assert.Equal(t, int32(1), onCloseCalls.Load())
}

func TestTokenWatcherListenFs_UpdateErrorDoesNotCloseWatcher(t *testing.T) {
	resetTokenSourceState(t)
	serviceAccountTokenCache.Store(tokenUpdateResult{value: "old-value"})

	watcher, err := fsnotify.NewWatcher()
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var updateCalls atomic.Int32
	var onCloseCalls atomic.Int32
	tw := &tokenWatcher{
		watcher: watcher,
		tokensDir: "tokens-dir",
		updateCache: func(string) error {
			updateCalls.Add(1)
			return errors.New("boom")
		},
		onClose: func() {
			onCloseCalls.Add(1)
		},
	}
	events := make(chan fsnotify.Event)
	errs := make(chan error)
	done := make(chan struct{})
	go func() {
		tw.listenFs(ctx, events, errs)
		close(done)
	}()

	events <- fsnotify.Event{Name: filepath.Join("tokens-dir", "..data"), Op: fsnotify.Create}
	assert.Eventually(t, func() bool {
		return updateCalls.Load() == 1
	}, time.Second, time.Millisecond*20)
	assert.Equal(t, tokenUpdateResult{value: "old-value"}, serviceAccountTokenCache.Load())
	assert.Equal(t, int32(0), onCloseCalls.Load())

	cancel()
	assert.Eventually(t, func() bool {
		return onCloseCalls.Load() == 1
	}, time.Second, time.Millisecond*20)
	<-done
}

func TestTokenWatcherListenFs_ErrorChannelDoesNotCloseWatcher(t *testing.T) {
	watcher, err := fsnotify.NewWatcher()
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var onCloseCalls atomic.Int32
	tw := &tokenWatcher{
		watcher: watcher,
		updateCache: func(string) error {
			return nil
		},
		onClose: func() {
			onCloseCalls.Add(1)
		},
	}
	events := make(chan fsnotify.Event)
	errs := make(chan error)
	done := make(chan struct{})
	go func() {
		tw.listenFs(ctx, events, errs)
		close(done)
	}()

	errs <- errors.New("watcher error")
	assert.Equal(t, int32(0), onCloseCalls.Load())

	cancel()
	<-done
	assert.Equal(t, int32(1), onCloseCalls.Load())
}
