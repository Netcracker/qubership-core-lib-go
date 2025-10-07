package tokensource

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testAudience          = "test-audience"
	tokensDir             string
	dataDir               string
	dataSymlinkPath       string
	tokenFile *os.File
)

func TestFileTokenSource(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()

	setupTokensDir(t)
	var err error
	firstValidToken := "first_valid_token"
	err = os.WriteFile(tokenFile.Name(), []byte(firstValidToken), 0)
	require.NoError(t, err)

	tokensSource, err = newFileTokenSource(ctx, tokensDir, filepath.Join(tokensDir, testAudience))
	require.NoError(t, err)

	token, err := GetToken(ctx, testAudience)
	require.NoError(t, err)
	assert.Equal(t, firstValidToken, token)

	token, err = GetTokenDefault(ctx)
	require.NoError(t, err)
	assert.Equal(t, firstValidToken, token)

	secondValidToken := "second_valid_token"
	err = os.WriteFile(tokenFile.Name(), []byte(secondValidToken), 0)
	require.NoError(t, err)

	refreshDataSymlink(t)

	time.Sleep(time.Millisecond * 50)

	token, err = GetToken(ctx, testAudience)
	require.NoError(t, err)
	assert.Equal(t, secondValidToken, token)

	token, err = GetTokenDefault(ctx)
	require.NoError(t, err)
	assert.Equal(t, secondValidToken, token)

	tokensSource = nil
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

	setupTokensDir(t)

	var newCalled atomic.Int32
	newFileTokenSource = func(_ context.Context, _, _ string) (*fileTokenSource, error) {
		newCalled.Add(1)
		return &fileTokenSource{
			tokensCache: map[string]*tokenCache{
				testAudience: {},
			},
			cancel: func() {},
		}, nil
	}

	var wg utils.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			_, err := GetToken(ctx, testAudience)
			require.NoError(t, err)
			wg.Done()
		}()
	}
	require.NoError(t, wg.Wait(ctx))

	assert.Equal(t, int32(1), newCalled.Load())

	newFileTokenSource = createFileTokenSource
	tokensSource = nil
}

func setupTokensDir(t *testing.T) {
	tokensDir = t.TempDir()

	var err error
	dataDir, err = os.MkdirTemp(tokensDir, "")
	require.NoError(t, err)

	dataSymlinkPath = filepath.Join(tokensDir, "..data")
	err = os.Symlink(dataDir, dataSymlinkPath)
	require.NoError(t, err)

	testAudienceTokenDir := filepath.Join(dataDir, testAudience)
	err = os.Mkdir(testAudienceTokenDir, 0775)
	require.NoError(t, err)

	tokenFile, err = os.Create(filepath.Join(testAudienceTokenDir, "token"))
	require.NoError(t, err)
	defer tokenFile.Close()

	testAudienceTokenDirLink := filepath.Join(tokensDir, testAudience)
	err = os.Symlink(filepath.Join(dataSymlinkPath, testAudience), testAudienceTokenDirLink)
	require.NoError(t, err)
}

func refreshDataSymlink(t *testing.T) {
	err := os.Remove(dataSymlinkPath)
	require.NoError(t, err)
	err = os.Symlink(dataDir, dataSymlinkPath)
	require.NoError(t, err)
}
