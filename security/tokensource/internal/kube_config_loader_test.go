package internal

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadKubeConfigFromCertificateAuthorityFile(t *testing.T) {
	dir := t.TempDir()
	caContent := []byte("-----BEGIN CERTIFICATE-----\ndummy-ca\n-----END CERTIFICATE-----")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cluster-ca.crt"), caContent, 0o600))

	configPath := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(configPath, []byte(`apiVersion: v1
kind: Config
current-context: test
contexts:
- context:
    cluster: test
    user: test
  name: test
clusters:
- cluster:
    server: https://api.example
    certificate-authority: cluster-ca.crt
  name: test
users:
- name: test
  user:
    token: kube-user-token
`), 0o600))
	t.Setenv("KUBECONFIG", configPath)

	creds, err := LoadKubeConfig()
	require.NoError(t, err)
	assert.Equal(t, caContent, creds.CertificateAuthorityData)
}

func TestLoadKubeConfigPrefersCertificateAuthorityDataOverFile(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "cluster-ca.crt")
	require.NoError(t, os.WriteFile(caFile, []byte("from-file"), 0o600))

	fromData := base64.StdEncoding.EncodeToString([]byte("from-data"))
	configPath := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(configPath, []byte(`apiVersion: v1
kind: Config
current-context: test
contexts:
- context:
    cluster: test
    user: test
  name: test
clusters:
- cluster:
    server: https://api.example
    certificate-authority: cluster-ca.crt
    certificate-authority-data: `+fromData+`
  name: test
users:
- name: test
  user:
    token: kube-user-token
`), 0o600))
	t.Setenv("KUBECONFIG", configPath)

	creds, err := LoadKubeConfig()
	require.NoError(t, err)
	assert.Equal(t, []byte("from-data"), creds.CertificateAuthorityData)
}

func TestLoadKubeConfigMissingCertificateAuthorityFile(t *testing.T) {
	path := writeKubeconfigFile(t, `apiVersion: v1
kind: Config
current-context: test
contexts:
- context:
    cluster: test
    user: test
  name: test
clusters:
- cluster:
    server: https://api.example
    certificate-authority: missing-ca.crt
  name: test
users:
- name: test
  user:
    token: kube-user-token
`)
	t.Setenv("KUBECONFIG", path)

	_, err := LoadKubeConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate-authority")
}

func TestLoadKubeConfigFromTokenUser(t *testing.T) {
	path := writeTestKubeconfig(t, "https://api.example/")
	t.Setenv("KUBECONFIG", path)

	creds, err := LoadKubeConfig()
	require.NoError(t, err)
	assert.Equal(t, "https://api.example", creds.ServerURL)
	assert.Equal(t, "kube-user-token", creds.UserToken)
	assert.True(t, creds.InsecureSkipTLSVerify)
}

func TestLoadKubeConfigFromIDTokenUser(t *testing.T) {
	path := writeKubeconfigFile(t, `apiVersion: v1
kind: Config
current-context: test
contexts:
- context:
    cluster: test
    user: test
  name: test
clusters:
- cluster:
    server: https://api.example
  name: test
users:
- name: test
  user:
    id-token: static-id-token
`)
	t.Setenv("KUBECONFIG", path)

	creds, err := LoadKubeConfig()
	require.NoError(t, err)
	assert.Equal(t, "static-id-token", creds.UserToken)
}

func TestLoadKubeConfigFromAccessTokenUser(t *testing.T) {
	path := writeKubeconfigFile(t, `apiVersion: v1
kind: Config
current-context: test
contexts:
- context:
    cluster: test
    user: test
  name: test
clusters:
- cluster:
    server: https://api.example
  name: test
users:
- name: test
  user:
    access-token: static-access-token
`)
	t.Setenv("KUBECONFIG", path)

	creds, err := LoadKubeConfig()
	require.NoError(t, err)
	assert.Equal(t, "static-access-token", creds.UserToken)
}

func TestLoadKubeConfigFromAuthProviderAccessToken(t *testing.T) {
	path := writeKubeconfigFile(t, `apiVersion: v1
kind: Config
current-context: test
contexts:
- context:
    cluster: test
    user: test
  name: test
clusters:
- cluster:
    server: https://api.example
  name: test
users:
- name: test
  user:
    auth-provider:
      name: gcp
      config:
        access-token: provider-access-token
`)
	t.Setenv("KUBECONFIG", path)

	creds, err := LoadKubeConfig()
	require.NoError(t, err)
	assert.Equal(t, "provider-access-token", creds.UserToken)
}

func TestLoadKubeConfigMissingCurrentContext(t *testing.T) {
	path := writeKubeconfigFile(t, `apiVersion: v1
kind: Config
contexts: []
clusters: []
users: []
`)
	t.Setenv("KUBECONFIG", path)

	_, err := LoadKubeConfig()
	assert.Error(t, err)
}

func TestLoadKubeConfigMissingFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KUBECONFIG", filepath.Join(dir, "missing-config"))

	_, err := LoadKubeConfig()
	assert.Error(t, err)
}

func TestResolveKubeConfigPathFromEnvList(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	firstPath := filepath.Join(first, "config")
	secondPath := filepath.Join(second, "config")
	require.NoError(t, os.WriteFile(secondPath, []byte("x"), 0o600))

	t.Setenv("KUBECONFIG", firstPath+string(os.PathListSeparator)+secondPath)
	path, err := resolveKubeConfigPath()
	require.NoError(t, err)
	assert.Equal(t, firstPath, path)
}

func TestLoadKubeConfigRejectsExecAuthentication(t *testing.T) {
	path := writeKubeconfigFile(t, `apiVersion: v1
kind: Config
current-context: test
contexts:
- context:
    cluster: test
    user: test
  name: test
clusters:
- cluster:
    server: https://api.example
  name: test
users:
- name: test
  user:
    exec:
      command: kubectl
      args:
        - oidc-login
        - get-token
`)
	t.Setenv("KUBECONFIG", path)

	_, err := LoadKubeConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exec")
	assert.Contains(t, err.Error(), "not supported")
}

func TestFindKubeConfigEntryByName(t *testing.T) {
	_, err := findKubeConfigEntryByName([]namedEntry{{Name: "other"}}, "missing")
	assert.Error(t, err)

	entry, err := findKubeConfigEntryByName([]namedEntry{{Name: "found"}}, "found")
	require.NoError(t, err)
	assert.Equal(t, "found", entry.Name)
}

func TestDecodeOptionalBase64(t *testing.T) {
	decoded, err := decodeOptionalBase64("")
	require.NoError(t, err)
	assert.Nil(t, decoded)

	encoded := "aGVsbG8="
	decoded, err = decodeOptionalBase64(encoded)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), decoded)

	decoded, err = decodeOptionalBase64("aGVs\nbG8=")
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), decoded)

	_, err = decodeOptionalBase64("!!!")
	assert.Error(t, err)
}

func TestResolveKubeConfigPathDefaultHome(t *testing.T) {
	t.Setenv("KUBECONFIG", "")
	path, err := resolveKubeConfigPath()
	require.NoError(t, err)
	assert.Contains(t, path, ".kube")
	assert.Contains(t, path, "config")
}
