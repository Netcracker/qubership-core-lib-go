package tokensource

import (
	"context"
	"errors"
	"os"
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

	fts, err := newFileTokenSource(ctx, tokenDir)
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

func TestGetToken(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()
	_, err := GetToken(ctx, "")
	assert.Error(t, err)
}

// func TestFileTokenSourceRace(t *testing.T) {
// 	ctx, cancelCtx := context.WithTimeout(context.Background(), 2*time.Second)
// 	defer cancelCtx()
//
// 	tokenDir := t.TempDir()
// 	tokenFilePath := tokenDir + "/token"
// 	tokenFile, err := os.Create(tokenFilePath)
// 	assert.NoError(t, err)
// 	defer tokenFile.Close()
//
// 	var newCalledCount atomic.Int32
// 	newFileTokenSource = func(ctx context.Context, tokenDir string) (*fileTokenSource, error) {
// 		newCalledCount.Add(1)
// 		return &fileTokenSource{}, nil
// 	}
// 	defer func() { newFileTokenSource = New }()
//
// 	var wg utils.WaitGroup
// 	for range 10 {
// 		wg.Add(1)
// 		go func() {
// 			_, err = getToken(ctx, path.Base(tokenDir), path.Dir(tokenDir))
// 			assert.NoError(t, err)
// 			wg.Done()
// 		}()
// 	}
//
// 	assert.NoError(t, wg.Wait(ctx))
// 	assert.Equal(t, int32(1), newCalledCount.Load())
// }

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

	fts, err := newFileTokenSource(ctx, tokenDir)
	assert.NoError(t, err)
	defer fts.Close()

	fts.watcher.Errors <- errors.New("mock error to see if the watcher doesn't stop after an error")
	fts.setError(nil)

	freshToken := "valid_token"
	_, err = tokenFile.Write([]byte(freshToken))
	assert.NoError(t, err)
	err = refreshDataSymlink(tokenFile.Name(), dataSymlinkPath)
	assert.NoError(t, err)

	time.Sleep(time.Millisecond * 50)

	token, err := fts.Token()
	assert.NoError(t, err)
	assert.Equal(t, freshToken, token)

	fts.setError(nil)

	err = os.Remove(tokenFilePath)
	assert.NoError(t, err)

	err = refreshDataSymlink(tokenFile.Name(), dataSymlinkPath)
	assert.NoError(t, err)

	time.Sleep(time.Millisecond * 50)

	assert.Error(t, fts.err)
}

func TestWrongDirectoryStructure(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()

	tokenDir := t.TempDir()
	tokenFilePath := tokenDir + "/test-audience"
	testFile, err := os.Create(tokenFilePath)
	assert.NoError(t, err)
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
