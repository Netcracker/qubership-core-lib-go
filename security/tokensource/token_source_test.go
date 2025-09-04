package tokensource

import (
	"context"
	"errors"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFileTokenSource(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()

	tokenDir := t.TempDir()
	tokenFilePath := tokenDir + "/token"
	dataSymlinkPath := tokenDir + "/..data"
	tokenFile, err := os.CreateTemp(tokenDir, "")
	assert.NoError(t, err)
	defer tokenFile.Close()
	err = os.Symlink(tokenFile.Name(), dataSymlinkPath)
	assert.NoError(t, err)
	err = os.Symlink(dataSymlinkPath, tokenFilePath)
	assert.NoError(t, err)

	firstValidToken := "first_valid_token"
	_, err = tokenFile.Write([]byte(firstValidToken))
	assert.NoError(t, err)

	fts, err := New(ctx, tokenDir)
	assert.NoError(t, err)
	defer fts.Close()
	token, err := fts.Token()
	assert.NoError(t, err)

	assert.Equal(t, firstValidToken, token)

	secondValidToken := "second_valid_token"
	_, err = tokenFile.WriteAt([]byte(secondValidToken), 0)
	assert.NoError(t, err)
	err = os.Remove(dataSymlinkPath)
	assert.NoError(t, err)
	err = os.Symlink(tokenFile.Name(), dataSymlinkPath)
	assert.NoError(t, err)

	time.Sleep(time.Millisecond * 50)
	token, err = fts.Token()
	assert.NoError(t, err)

	assert.Equal(t, secondValidToken, token)
}

func TestFileTokenSourceRace(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()

	tokenDir := t.TempDir()
	tokenFilePath := tokenDir + "/token"
	tokenFile, err := os.Create(tokenFilePath)
	assert.NoError(t, err)
	defer tokenFile.Close()

	var newCalledCount atomic.Int32
	newFileTokenSource = func(ctx context.Context, tokenDir string) (*fileTokenSource, error) {
		newCalledCount.Add(1)
		return &fileTokenSource{}, nil
	}

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			_, err = getToken(ctx, path.Base(tokenDir), path.Dir(tokenDir))
			assert.NoError(t, err)
			wg.Done()
		}()
	}

	select {
	case <-wait(wg.Wait):
	case <-ctx.Done():
		t.Fatal("context timed out waiting for parallel getToken() calls")
	}

	assert.Equal(t, int32(1), newCalledCount.Load())
}

func wait(f func()) chan struct{} {
	ch := make(chan struct{})
	go func() {
		f()
		ch <- struct{}{}
	}()
	return ch
}

func TestErrChannel(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()

	tokenDir := t.TempDir()
	tokenFilePath := tokenDir + "/token"
	dataSymlinkPath := tokenDir + "/..data"
	tokenFile, err := os.CreateTemp(tokenDir, "")
	assert.NoError(t, err)
	defer tokenFile.Close()
	err = os.Symlink(tokenFile.Name(), dataSymlinkPath)
	assert.NoError(t, err)
	err = os.Symlink(dataSymlinkPath, tokenFilePath)
	assert.NoError(t, err)

	fts, err := New(ctx, tokenDir)
	assert.NoError(t, err)
	defer fts.Close()

	fts.watcher.Errors <- errors.New("mock error to see if the watcher doesn't stop after an error")
	fts.setError(nil)

	freshToken := "valid_token"
	_, err = tokenFile.Write([]byte(freshToken))
	assert.NoError(t, err)
	err = os.Remove(dataSymlinkPath)
	assert.NoError(t, err)
	err = os.Symlink(tokenFile.Name(), dataSymlinkPath)
	assert.NoError(t, err)

	time.Sleep(time.Millisecond * 50)

	token, err := fts.Token()
	assert.NoError(t, err)

	assert.Equal(t, freshToken, token)
}
