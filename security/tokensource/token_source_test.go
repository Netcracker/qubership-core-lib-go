package tokensource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileTokenSource(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()

	tokenDir := t.TempDir()
	tokenFilePath := tokenDir + "/token"
	dataSymlinkPath := tokenDir + "/..data"
	tokenFile, err := os.CreateTemp(tokenDir, "")
	require.NoError(t, err)
	defer tokenFile.Close()
	err = os.Symlink(tokenFile.Name(), dataSymlinkPath)
	require.NoError(t, err)
	err = os.Symlink(dataSymlinkPath, tokenFilePath)
	require.NoError(t, err)

	firstValidToken := "first_valid_token"
	_, err = tokenFile.Write([]byte(firstValidToken))
	require.NoError(t, err)

	fts, err := newFileTokenSource(ctx, tokenDir)
	require.NoError(t, err)
	defer fts.Close()
	token, err := fts.Token()
	require.NoError(t, err)

	assert.Equal(t, firstValidToken, token)

	secondValidToken := "second_valid_token"
	_, err = tokenFile.WriteAt([]byte(secondValidToken), 0)
	require.NoError(t, err)
	err = os.Remove(dataSymlinkPath)
	require.NoError(t, err)
	err = os.Symlink(tokenFile.Name(), dataSymlinkPath)
	require.NoError(t, err)

	time.Sleep(time.Millisecond * 50)
	token, err = fts.Token()
	require.NoError(t, err)

	assert.Equal(t, secondValidToken, token)
}

func TestGetToken(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()
	_, err := GetToken(ctx, "")
	assert.Error(t, err)
}

func TestFileTokenSourceRace(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelCtx()

	tokenDir := t.TempDir()
	tokenFilePath := tokenDir + "/token"
	tokenFile, err := os.Create(tokenFilePath)
	require.NoError(t, err)
	defer tokenFile.Close()

	var wg utils.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			_, err = getToken(ctx, filepath.Base(tokenDir), filepath.Dir(tokenDir))
			require.NoError(t, err)
			wg.Done()
		}()
	}
	require.NoError(t, wg.Wait(ctx))

	assert.Equal(t, 1, len(tokenSources))
}

func TestErrChannel(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()

	tokenDir := t.TempDir()
	tokenFilePath := tokenDir + "/token"
	dataSymlinkPath := tokenDir + "/..data"
	tokenFile, err := os.CreateTemp(tokenDir, "")
	require.NoError(t, err)
	defer tokenFile.Close()
	err = os.Symlink(tokenFile.Name(), dataSymlinkPath)
	require.NoError(t, err)
	err = os.Symlink(dataSymlinkPath, tokenFilePath)
	require.NoError(t, err)

	fts, err := newFileTokenSource(ctx, tokenDir)
	require.NoError(t, err)
	defer fts.Close()

	fts.watcher.Errors <- errors.New("mock error to see if the watcher doesn't stop after an error")
	fts.setError(nil)

	freshToken := "valid_token"
	_, err = tokenFile.Write([]byte(freshToken))
	require.NoError(t, err)
	err = refreshDataSymlink(tokenFile.Name(), dataSymlinkPath)
	require.NoError(t, err)

	time.Sleep(time.Millisecond * 50)

	token, err := fts.Token()
	require.NoError(t, err)
	assert.Equal(t, freshToken, token)

	fts.setError(nil)

	err = os.Remove(tokenFilePath)
	require.NoError(t, err)

	err = refreshDataSymlink(tokenFile.Name(), dataSymlinkPath)
	require.NoError(t, err)

	time.Sleep(time.Millisecond * 50)

	assert.Error(t, fts.err)
}

func TestWrongDirectoryStructure(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()

	tokenDir := t.TempDir()
	tokenFilePath := tokenDir + "/test-audience"
	testFile, err := os.Create(tokenFilePath)
	require.NoError(t, err)
	defer testFile.Close()
	_, err = getToken(ctx, "test-audience", tokenDir)
	assert.Error(t, err)
}

func refreshDataSymlink(tokenFile, dataSymlinkPath string) error {
	err := os.Remove(dataSymlinkPath)
	if err != nil {
		return err
	}
	err = os.Symlink(tokenFile, dataSymlinkPath)
	if err != nil {
		return err
	}
	return nil
}
