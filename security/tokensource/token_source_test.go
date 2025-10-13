package tokensource

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testAudience                  = "test-audience"
	tokensDir                     string
	audienceTokensDataDir         string
	audienceTokensDataSymlinkPath string
	saLinkPath                    string
	tokenFile                     *os.File
)

func TestFileTokenSource(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(t.Context(), time.Minute)
	defer cancelCtx()

	setupTokensDir(t)
	var err error
	firstValidToken := "first_valid_token"
	err = os.WriteFile(tokenFile.Name(), []byte(firstValidToken), 0)
	require.NoError(t, err)

	DefaultAudienceTokensDir = tokensDir
	DefaultServiceAccountDir = filepath.Join(tokensDir, testAudience)

	token, err := GetAudienceToken(ctx, testAudience)
	require.NoError(t, err)
	assert.Equal(t, firstValidToken, token)

	token, err = GetServiceAccountToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, firstValidToken, token)

	secondValidToken := "second_valid_token"
	err = os.WriteFile(tokenFile.Name(), []byte(secondValidToken), 0)
	require.NoError(t, err)

	refreshDataSymlink(t, audienceTokensDataDir, audienceTokensDataSymlinkPath)
	time.Sleep(time.Millisecond * 50)

	token, err = GetAudienceToken(ctx, testAudience)
	require.NoError(t, err)
	assert.Equal(t, secondValidToken, token)

	refreshDataSymlink(t, tokenFile.Name(), saLinkPath)
	time.Sleep(time.Millisecond * 50)

	token, err = GetServiceAccountToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, secondValidToken, token)

	audienceTokensWatcher.Store(nil)
	serviceAccountTokenWatcher.Store(nil)
}

func TestGetToken(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer cancelCtx()
	_, err := GetAudienceToken(ctx, "")
	assert.Error(t, err)
}

func setupTokensDir(t *testing.T) {
	tokensDir = t.TempDir()

	var err error
	audienceTokensDataDir, err = os.MkdirTemp(tokensDir, "")
	require.NoError(t, err)

	audienceTokensDataSymlinkPath = filepath.Join(tokensDir, "..data")
	err = os.Symlink(audienceTokensDataDir, audienceTokensDataSymlinkPath)
	require.NoError(t, err)

	testAudienceTokenDir := filepath.Join(audienceTokensDataDir, testAudience)
	err = os.Mkdir(testAudienceTokenDir, 0775)
	require.NoError(t, err)

	tokenFile, err = os.Create(filepath.Join(testAudienceTokenDir, "token"))
	require.NoError(t, err)
	defer tokenFile.Close()

	testAudienceTokenDirLink := filepath.Join(tokensDir, testAudience)
	err = os.Symlink(filepath.Join(audienceTokensDataSymlinkPath, testAudience), testAudienceTokenDirLink)
	require.NoError(t, err)

	saLinkPath = filepath.Join(tokensDir, testAudience, "..data")
	err = os.Symlink(tokenFile.Name(), saLinkPath)
	require.NoError(t, err)
}

func refreshDataSymlink(t *testing.T, dataDir string, symlinkPath string) {
	err := os.Remove(symlinkPath)
	require.NoError(t, err)
	err = os.Symlink(dataDir, symlinkPath)
	require.NoError(t, err)
}
