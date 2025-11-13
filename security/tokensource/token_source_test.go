package tokensource

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	saTokenStorage   *serviceAccountTokenStorage
	audTokensStorage *audienceTokensStorage
)

func beforeEach(t *testing.T) {
	var err error

	saTokenStorage, err = newServiceAccountTokenStorage(t.TempDir())
	assert.NoError(t, err)
	DefaultServiceAccountDir = saTokenStorage.serviceAccountTokenDir
	logger.Infof("service account token dir is %s", saTokenStorage.serviceAccountTokenDir)

	audTokensStorage, err = newAudienceTokensStorage(t.TempDir())
	assert.NoError(t, err)
	DefaultAudienceTokensDir = audTokensStorage.audienceTokensDir
	logger.Infof("audience tokens dir is %s", audTokensStorage.audienceTokensDir)
}
func afterEach(_ *testing.T) {
	_ = saTokenStorage.clear()
	_ = audTokensStorage.clear()
}
func TestMain(m *testing.M) {
	exitCode := m.Run()
	os.Exit(exitCode)
}
func TestServiceAccountToken(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountTokenInitialValue := "service_account_token_initial_value"
	err := saTokenStorage.saveTokenValue(serviceAccountTokenInitialValue)
	assert.NoError(t, err)

	token, err := GetServiceAccountToken(ctx)
	assert.NoError(t, err)
	assert.Equal(t, serviceAccountTokenInitialValue, token)

	serviceAccountTokenSecondValue := "service_account_token_second_value"
	err = saTokenStorage.saveTokenValue(serviceAccountTokenSecondValue)
	assert.NoError(t, err)

	token, err = GetServiceAccountToken(ctx)
	assert.NoError(t, err)
	assert.Equal(t, serviceAccountTokenSecondValue, token)
}
func TestNoServiceAccountToken(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	err := saTokenStorage.deleteTokenFile()
	assert.NoError(t, err)

	_, err = GetServiceAccountToken(ctx)
	assert.ErrorContains(t, err, "failed to get token default kubernetes service account token: failed to read token at path")

	err = saTokenStorage.saveTokenValue("value")
	assert.NoError(t, err)

	token, err := GetServiceAccountToken(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "value", token)

	err = saTokenStorage.deleteTokenFile()
	assert.NoError(t, err)

	_, err = GetServiceAccountToken(ctx)
	assert.ErrorContains(t, err, "failed to get token default kubernetes service account token: failed to read token at path")
}
func TestNoServiceAccountTokenDir(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	err := saTokenStorage.clear()
	assert.NoError(t, err)

	_, err = GetServiceAccountToken(ctx)
	assert.ErrorContains(t, err, "failed to create token watcher: failed to add path")
}
func TestAudienceTokens(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	netcrackerTokenInitialValue := "netcracker_token_initial_value"
	err := audTokensStorage.saveTokenValue(AudienceNetcracker, netcrackerTokenInitialValue)
	assert.NoError(t, err)

	dbaasTokenInitialValue := "dbaas_token_initial_value"
	err = audTokensStorage.saveTokenValue(AudienceDBaaS, dbaasTokenInitialValue)
	assert.NoError(t, err)

	token, err := GetAudienceToken(ctx, AudienceNetcracker)
	assert.NoError(t, err)
	assert.Equal(t, netcrackerTokenInitialValue, token)

	token, err = GetAudienceToken(ctx, AudienceDBaaS)
	assert.NoError(t, err)
	assert.Equal(t, dbaasTokenInitialValue, token)

	netcrackerTokenSecondValue := "netcracker_token_second_value"
	err = audTokensStorage.saveTokenValue(AudienceNetcracker, netcrackerTokenSecondValue)
	assert.NoError(t, err)

	token, err = GetAudienceToken(ctx, AudienceNetcracker)
	assert.NoError(t, err)
	assert.Equal(t, netcrackerTokenSecondValue, token)

	dbaasTokenSecondValue := "dbaas_token_second_value"
	err = audTokensStorage.saveTokenValue(AudienceDBaaS, dbaasTokenSecondValue)
	assert.NoError(t, err)

	token, err = GetAudienceToken(ctx, AudienceDBaaS)
	assert.NoError(t, err)
	assert.Equal(t, dbaasTokenSecondValue, token)
}
func TestNoAudienceToken(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	_, err := GetAudienceToken(ctx, AudienceNetcracker)
	assert.ErrorContains(t, err, "token with audience netcracker was not found")

	err = audTokensStorage.saveTokenValue(AudienceNetcracker, "value")
	assert.NoError(t, err)

	token, err := GetAudienceToken(ctx, AudienceNetcracker)
	assert.NoError(t, err)
	assert.Equal(t, "value", token)

	err = audTokensStorage.deleteTokenFile(AudienceNetcracker)
	assert.NoError(t, err)

	_, err = GetAudienceToken(ctx, AudienceNetcracker)
	assert.ErrorContains(t, err, "failed to get token by audience: netcracker: failed to read token at path")
}
func TestNoAudienceTokensDir(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	err := audTokensStorage.clear()
	assert.NoError(t, err)

	_, err = GetAudienceToken(ctx, AudienceNetcracker)
	assert.ErrorContains(t, err, "failed to create token watcher: failed to refresh tokens cache: failed to get dir entries from tokenDir")

}
func TestEmptyAudience(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	_, err := GetAudienceToken(ctx, "")
	assert.ErrorContains(t, err, "audience is empty")
}

const dataSymlinkName = "..data"

type tokenStorage struct {
	rootDir        string
	dataDir        string
	dataDirSymlink string
}
type serviceAccountTokenStorage struct {
	tokenStorage
	tokenInfo              *tokenStorageInfo
	serviceAccountTokenDir string
}
type audienceTokensStorage struct {
	tokenStorage
	tokenInfos        map[string]*tokenStorageInfo
	audienceTokensDir string
}
type tokenStorageInfo struct {
	tokenDir     string
	tokenSymlink string
	tokenFile    *os.File
}

func newServiceAccountTokenStorage(rootDir string) (*serviceAccountTokenStorage, error) {
	serviceAccountTokenDir := filepath.Join(rootDir, "kubernetes.io", "serviceaccount")
	err := os.MkdirAll(serviceAccountTokenDir, 0775)
	if err != nil {
		return nil, fmt.Errorf("error creating service account token dir: %w", err)
	}
	dataDir, err := os.MkdirTemp(serviceAccountTokenDir, "")
	if err != nil {
		return nil, fmt.Errorf("error creating service account token data dir: %w", err)
	}
	dataDirSymlink := filepath.Join(serviceAccountTokenDir, dataSymlinkName)
	err = os.Symlink(dataDir, dataDirSymlink)
	if err != nil {
		return nil, fmt.Errorf("error creating service account token data dir symlink: %w", err)
	}
	serviceAccountTokenStorage := &serviceAccountTokenStorage{
		tokenStorage: tokenStorage{
			rootDir:        rootDir,
			dataDir:        dataDir,
			dataDirSymlink: dataDirSymlink,
		},
		serviceAccountTokenDir: serviceAccountTokenDir,
	}
	err = serviceAccountTokenStorage.createTokenFile()
	if err != nil {
		return nil, err
	}
	return serviceAccountTokenStorage, nil
}
func (s *serviceAccountTokenStorage) createTokenFile() error {
	if s.tokenInfo != nil {
		return nil
	}
	var err error
	tokenInfo := &tokenStorageInfo{}
	tokenInfo.tokenDir = s.dataDir
	tokenInfo.tokenFile, err = os.Create(filepath.Join(tokenInfo.tokenDir, "token"))
	if err != nil {
		return fmt.Errorf("error creating service account token file: %w", err)
	}
	defer func() { _ = tokenInfo.tokenFile.Close() }()
	tokenInfo.tokenSymlink = filepath.Join(s.serviceAccountTokenDir, "token")
	_, err = os.Lstat(tokenInfo.tokenSymlink)
	if err == nil {
		s.tokenInfo = tokenInfo
		return nil
	}
	err = os.Symlink(filepath.Join(s.dataDirSymlink, "token"), tokenInfo.tokenSymlink)
	if err != nil {
		return fmt.Errorf("error creating service account token file symlink: %w", err)
	}
	s.tokenInfo = tokenInfo
	return nil
}
func (s *serviceAccountTokenStorage) saveTokenValue(token string) error {
	err := s.createTokenFile()
	if err != nil {
		return err
	}
	err = os.WriteFile(s.tokenInfo.tokenFile.Name(), []byte(token), 0)
	if err != nil {
		return fmt.Errorf("error saving token value into service account token file: %w", err)
	}
	return s.refreshSymlink()
}
func (s *serviceAccountTokenStorage) deleteTokenFile() error {
	var err error
	if s.tokenInfo == nil {
		return nil
	}
	err = os.Remove(s.tokenInfo.tokenFile.Name())
	if err != nil {
		return fmt.Errorf("error deleting service account token file: %w", err)
	}
	s.tokenInfo = nil
	return s.refreshSymlink()
}
func (s *serviceAccountTokenStorage) clear() error {
	err := os.RemoveAll(s.rootDir)
	if err != nil {
		return fmt.Errorf("error clearing service account token dir: %w", err)
	}
	return nil
}
func (s *serviceAccountTokenStorage) refreshSymlink() error {
	err := os.Remove(s.dataDirSymlink)
	if err != nil {
		return fmt.Errorf("error deleting service account token data dir symlink: %w", err)
	}
	err = os.Symlink(s.dataDir, s.dataDirSymlink)
	if err != nil {
		return fmt.Errorf("error creating service account token data dir symlink: %w", err)
	}
	time.Sleep(time.Millisecond * 50)
	return nil
}
func newAudienceTokensStorage(rootDir string) (*audienceTokensStorage, error) {
	audienceTokensDir := filepath.Join(rootDir, "tokens")
	err := os.MkdirAll(audienceTokensDir, 0775)
	if err != nil {
		return nil, fmt.Errorf("error creating audience tokens dir: %w", err)
	}
	dataDir, err := os.MkdirTemp(audienceTokensDir, "")
	if err != nil {
		return nil, fmt.Errorf("error creating audience tokens data dir: %w", err)
	}
	dataDirSymlink := filepath.Join(audienceTokensDir, dataSymlinkName)
	err = os.Symlink(dataDir, dataDirSymlink)
	if err != nil {
		return nil, fmt.Errorf("error creating audience tokens data dir symlink: %w", err)
	}
	return &audienceTokensStorage{
		tokenStorage: tokenStorage{
			rootDir:        rootDir,
			dataDir:        dataDir,
			dataDirSymlink: dataDirSymlink,
		},
		audienceTokensDir: audienceTokensDir,
		tokenInfos:        make(map[string]*tokenStorageInfo),
	}, nil
}
func (s *audienceTokensStorage) createTokenFile(audience string) (*tokenStorageInfo, error) {
	tokenInfo, ok := s.tokenInfos[audience]
	if ok {
		return tokenInfo, nil
	}
	var err error
	tokenInfo = &tokenStorageInfo{}
	tokenInfo.tokenDir = filepath.Join(s.dataDir, audience)
	err = os.MkdirAll(tokenInfo.tokenDir, 0775)
	if err != nil {
		return nil, fmt.Errorf("error creating audience %s token dir: %w", audience, err)
	}
	tokenInfo.tokenFile, err = os.Create(filepath.Join(tokenInfo.tokenDir, "token"))
	if err != nil {
		return nil, fmt.Errorf("error creating audience %s token file: %w", audience, err)
	}
	defer func() { _ = tokenInfo.tokenFile.Close() }()
	tokenInfo.tokenSymlink = filepath.Join(s.audienceTokensDir, audience)
	_, err = os.Lstat(tokenInfo.tokenSymlink)
	if err == nil {
		s.tokenInfos[audience] = tokenInfo
		return tokenInfo, nil
	}
	err = os.Symlink(filepath.Join(s.dataDirSymlink, audience), tokenInfo.tokenSymlink)
	if err != nil {
		return nil, fmt.Errorf("error creating audience %s token file symlink: %w", audience, err)
	}
	s.tokenInfos[audience] = tokenInfo
	return tokenInfo, nil
}
func (s *audienceTokensStorage) saveTokenValue(audience string, token string) error {
	tokenInfo, err := s.createTokenFile(audience)
	if err != nil {
		return err
	}
	err = os.WriteFile(tokenInfo.tokenFile.Name(), []byte(token), 0)
	if err != nil {
		return fmt.Errorf("error saving token value into audience %s token file: %w", audience, err)
	}
	return s.refreshSymlink()
}
func (s *audienceTokensStorage) deleteTokenFile(audience string) error {
	var err error
	tokenInfo, ok := s.tokenInfos[audience]
	if !ok {
		return nil
	}
	err = os.Remove(filepath.Join(tokenInfo.tokenDir, "token"))
	if err != nil {
		return fmt.Errorf("error deleting audience %s token file: %w", audience, err)
	}
	delete(s.tokenInfos, audience)
	return s.refreshSymlink()
}
func (s *audienceTokensStorage) clear() error {
	err := os.RemoveAll(s.rootDir)
	if err != nil {
		return fmt.Errorf("error clearing audience tokens dir: %w", err)
	}
	return nil
}
func (s *audienceTokensStorage) refreshSymlink() error {
	err := os.Remove(s.dataDirSymlink)
	if err != nil {
		return fmt.Errorf("error deleting audience tokens data dir symlink: %w", err)
	}
	err = os.Symlink(s.dataDir, s.dataDirSymlink)
	if err != nil {
		return fmt.Errorf("error creating audience tokens data dir symlink: %w", err)
	}
	time.Sleep(time.Millisecond * 50)
	return nil
}
