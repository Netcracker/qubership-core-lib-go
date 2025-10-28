package test

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const dataSymlinkName = "..data"

type TokenStorage struct {
	RootDir        string
	dataDir        string
	dataDirSymlink string
}
type ServiceAccountTokenStorage struct {
	TokenStorage
	tokenInfo              *TokenStorageInfo
	ServiceAccountTokenDir string
}
type AudienceTokensStorage struct {
	TokenStorage
	tokenInfos        map[string]*TokenStorageInfo
	AudienceTokensDir string
}
type TokenStorageInfo struct {
	tokenDir     string
	tokenSymlink string
	TokenFile    *os.File
}

func NewServiceAccountTokenStorage(rootDir string) (*ServiceAccountTokenStorage, error) {
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
	serviceAccountTokenStorage := &ServiceAccountTokenStorage{
		TokenStorage: TokenStorage{
			RootDir:        rootDir,
			dataDir:        dataDir,
			dataDirSymlink: dataDirSymlink,
		},
		ServiceAccountTokenDir: serviceAccountTokenDir,
	}
	err = serviceAccountTokenStorage.createTokenFile()
	if err != nil {
		return nil, err
	}
	return serviceAccountTokenStorage, nil
}
func (s *ServiceAccountTokenStorage) createTokenFile() error {
	if s.tokenInfo != nil {
		return nil
	}
	var err error
	tokenInfo := &TokenStorageInfo{}
	tokenInfo.tokenDir = s.dataDir
	tokenInfo.TokenFile, err = os.Create(filepath.Join(tokenInfo.tokenDir, "token"))
	if err != nil {
		return fmt.Errorf("error creating service account token file: %w", err)
	}
	defer tokenInfo.TokenFile.Close()
	tokenInfo.tokenSymlink = filepath.Join(s.ServiceAccountTokenDir, "token")
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
func (s *ServiceAccountTokenStorage) SaveTokenValue(token string) (error, bool) {
	err := s.createTokenFile()
	if err != nil {
		return err, false
	}
	err = os.WriteFile(s.tokenInfo.TokenFile.Name(), []byte(token), 0)
	if err != nil {
		return fmt.Errorf("error saving token value into service account token file: %w", err), false
	}
	return s.refreshToken(), true
}
func (s *ServiceAccountTokenStorage) DeleteTokenFile() (error, bool) {
	var err error
	err = os.Remove(s.tokenInfo.TokenFile.Name())
	if err != nil {
		return fmt.Errorf("error deleting service account token file: %w", err), false
	}
	s.tokenInfo = nil
	return s.refreshToken(), true
}
func (s *ServiceAccountTokenStorage) refreshToken() error {
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
func NewAudienceTokensStorage(rootDir string) (*AudienceTokensStorage, error) {
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
	return &AudienceTokensStorage{
		TokenStorage: TokenStorage{
			RootDir:        rootDir,
			dataDir:        dataDir,
			dataDirSymlink: dataDirSymlink,
		},
		AudienceTokensDir: audienceTokensDir,
		tokenInfos:        make(map[string]*TokenStorageInfo),
	}, nil
}
func (s *AudienceTokensStorage) createTokenFile(audience string) (*TokenStorageInfo, error) {
	tokenInfo, ok := s.tokenInfos[audience]
	if ok {
		return tokenInfo, nil
	}
	var err error
	tokenInfo = &TokenStorageInfo{}
	tokenInfo.tokenDir = filepath.Join(s.dataDir, audience)
	err = os.MkdirAll(tokenInfo.tokenDir, 0775)
	if err != nil {
		return nil, fmt.Errorf("error creating audience %s token dir: %w", audience, err)
	}
	tokenInfo.TokenFile, err = os.Create(filepath.Join(tokenInfo.tokenDir, "token"))
	if err != nil {
		return nil, fmt.Errorf("error creating audience %s token file: %w", audience, err)
	}
	defer tokenInfo.TokenFile.Close()
	tokenInfo.tokenSymlink = filepath.Join(s.AudienceTokensDir, audience)
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
func (s *AudienceTokensStorage) SaveTokenValue(audience string, token string) (error, bool) {
	tokenInfo, err := s.createTokenFile(audience)
	if err != nil {
		return err, false
	}
	err = os.WriteFile(tokenInfo.TokenFile.Name(), []byte(token), 0)
	if err != nil {
		return fmt.Errorf("error saving token value into audience %s token file: %w", audience, err), false
	}
	return s.refreshTokens(), true
}
func (s *AudienceTokensStorage) DeleteTokenFile(audience string) (error, bool) {
	var err error
	tokenInfo, ok := s.tokenInfos[audience]
	if !ok {
		return nil, false
	}
	err = os.Remove(filepath.Join(tokenInfo.tokenDir, "token"))
	if err != nil {
		return fmt.Errorf("error deleting audience %s token file: %w", audience, err), false
	}
	delete(s.tokenInfos, audience)
	return s.refreshTokens(), true
}
func (s *AudienceTokensStorage) refreshTokens() error {
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
