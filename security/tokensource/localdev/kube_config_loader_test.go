package localdev

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestRunExecCredential(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "token.json")
	require.NoError(t, os.WriteFile(jsonPath, []byte(`{"status":{"token":"exec-token"}}`), 0o600))

	var command string
	var args []any
	if runtime.GOOS == "windows" {
		command = "cmd"
		args = []any{"/c", "type", jsonPath}
	} else {
		command = "cat"
		args = []any{jsonPath}
	}

	execCfg := map[string]any{
		kubeConfigCommand: command,
		kubeConfigArgs:    args,
	}

	token, err := runExecCredential(execCfg)
	require.NoError(t, err)
	assert.Equal(t, "exec-token", token)
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

	_, err = decodeOptionalBase64("!!!")
	assert.Error(t, err)
}
