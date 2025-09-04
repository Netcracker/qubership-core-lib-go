package tokensource

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFileTokenSource(t *testing.T) {
	tokenDir := t.TempDir()
	tokenFilePath := tokenDir + "/token"
	dataSymlinkPath := tokenDir + "/..data"
	tokenFile, err := os.CreateTemp(tokenDir, "")
	if err != nil {
		assert.NoError(t, err)
	}
	defer tokenFile.Close()
	err = os.Symlink(tokenFile.Name(), dataSymlinkPath)
	if err != nil {
		assert.NoError(t, err)
	}
	err = os.Symlink(dataSymlinkPath, tokenFilePath)
	if err != nil {
		assert.NoError(t, err)
	}

	firstValidToken := "first_valid_token"
	_, err = tokenFile.Write([]byte(firstValidToken))
	if err != nil {
		assert.NoError(t, err)
	}

	fts, err := New(context.Background(), tokenDir)
	if err != nil {
		assert.NoError(t, err)
	}
	token, err := fts.Token()
	if err != nil {
		assert.NoError(t, err)
	}

	assert.Equal(t, firstValidToken, token)

	secondValidToken := "second_valid_token"
	_, err = tokenFile.WriteAt([]byte(secondValidToken), 0)
	if err != nil {
		assert.NoError(t, err)
	}
	err = os.Remove(dataSymlinkPath)
	if err != nil {
		assert.NoError(t, err)
	}
	err = os.Symlink(tokenFile.Name(), dataSymlinkPath)
	if err != nil {
		assert.NoError(t, err)
	}

	time.Sleep(time.Millisecond * 50)
	token, err = fts.Token()
	if err != nil {
		assert.NoError(t, err)
	}

	assert.Equal(t, secondValidToken, token)
}

func TestFileTokenSourceRace(t *testing.T) {
	tokenDir := t.TempDir()
	tokenFilePath := tokenDir + "/token"
	dataSymlinkPath := tokenDir + "/..data"
	tokenFile, err := os.CreateTemp(tokenDir, "")
	if err != nil {
		assert.NoError(t, err)
	}
	defer tokenFile.Close()
	err = os.Symlink(tokenFile.Name(), dataSymlinkPath)
	if err != nil {
		assert.NoError(t, err)
	}
	err = os.Symlink(dataSymlinkPath, tokenFilePath)
	if err != nil {
		assert.NoError(t, err)
	}

	var newCalledCount atomic.Int32
	newFileTokenSource = func(ctx context.Context, tokenDir string) (*fileTokenSource, error) {
		newCalledCount.Add(1)
		return &fileTokenSource{}, nil
	}

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			_, err = New(context.Background(), tokenDir)
			if err != nil {
				panic(err)
			}
			wg.Done()
		}()
	}
	wg.Wait()

	assert.LessOrEqual(t, newCalledCount.Load(), int32(1))
}
