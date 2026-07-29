package localdev

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTlsConfigPaths(t *testing.T) {
	cfg := tlsConfig(nil)
	require.NotNil(t, cfg)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)

	insecure := tlsConfig(&KubeConfigCredentials{InsecureSkipTLSVerify: true})
	require.NotNil(t, insecure)
	assert.True(t, insecure.InsecureSkipVerify)

	noCA := tlsConfig(&KubeConfigCredentials{})
	require.NotNil(t, noCA)

	caPEM := mustGenerateTestCAPEM(t)
	withCA := tlsConfig(&KubeConfigCredentials{CertificateAuthorityData: caPEM})
	require.NotNil(t, withCA)
	assert.NotNil(t, withCA.RootCAs)

	badCA := tlsConfig(&KubeConfigCredentials{CertificateAuthorityData: []byte("not-a-cert")})
	require.NotNil(t, badCA)
	assert.Nil(t, badCA.RootCAs)
}

func TestCertPoolFromBytes(t *testing.T) {
	caPEM := mustGenerateTestCAPEM(t)
	pool, err := certPoolFromBytes(caPEM)
	require.NoError(t, err)
	require.NotNil(t, pool)

	_, err = certPoolFromBytes([]byte("garbage"))
	assert.Error(t, err)

	_, err = certPoolFromBytes([]byte{})
	assert.Error(t, err)
}

func TestNewHTTPClientVariants(t *testing.T) {
	creds := &KubeConfigCredentials{
		ServerURL:             "https://api.example",
		InsecureSkipTLSVerify: true,
	}
	client := newHTTPClient(creds)
	require.NotNil(t, client)
	assert.Equal(t, httpRequestTimeout, client.Timeout)

	insecureClient := newInsecureIdpHTTPClient()
	require.NotNil(t, insecureClient)
	assert.Equal(t, httpRequestTimeout, insecureClient.Timeout)
}

func mustGenerateTestCAPEM(t *testing.T) []byte {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
