package localdev

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func writeTestKubeconfig(t *testing.T, serverURL string) string {
	return writeKubeconfigFile(t, `apiVersion: v1
kind: Config
current-context: test
contexts:
- context:
    cluster: test
    user: test
  name: test
clusters:
- cluster:
    server: `+serverURL+`
    insecure-skip-tls-verify: true
  name: test
users:
- name: test
  user:
    token: kube-user-token
`)
}

func writeKubeconfigFile(t *testing.T, content string) string {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func buildTestJWT(exp time.Time) string {
	payload, err := json.Marshal(map[string]int64{"exp": exp.Unix()})
	if err != nil {
		panic(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return "header." + encoded + ".signature"
}
