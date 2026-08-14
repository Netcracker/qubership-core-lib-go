package internal

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
)

func newHTTPClient(credentials *KubeConfigCredentials) *http.Client {
	return &http.Client{
		Timeout:   httpRequestTimeout,
		Transport: newHTTPTransport(tlsConfig(credentials)),
	}
}

func newInsecureIdpHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   httpRequestTimeout,
		Transport: newHTTPTransport(localDevInsecureTLSConfig()),
	}
}

func newHTTPTransport(tlsCfg *tls.Config) *http.Transport {
	return &http.Transport{
		DialContext:           (&net.Dialer{Timeout: httpRequestTimeout}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          httpMaxIdleConns,
		IdleConnTimeout:       httpIdleConnTimeout,
		TLSHandshakeTimeout:   httpTLSHandshakeTimeout,
		ExpectContinueTimeout: httpExpectContinueTimeout,
		TLSClientConfig:       tlsCfg,
	}
}

func tlsConfig(credentials *KubeConfigCredentials) *tls.Config {
	if credentials == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if credentials.InsecureSkipTLSVerify {
		return localDevInsecureTLSConfig()
	}
	if len(credentials.CertificateAuthorityData) == 0 {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	pool, err := certPoolFromBytes(credentials.CertificateAuthorityData)
	if err != nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
}

// localDevInsecureTLSConfig is for local development only (kubeconfig insecure-skip-tls-verify or IdP private CA).
func localDevInsecureTLSConfig() *tls.Config {
	return &tls.Config{ // NOSONAR
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
}

func certPoolFromBytes(data []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if pool.AppendCertsFromPEM(data) {
		return pool, nil
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig CA: %w", err)
	}
	pool.AddCert(cert)

	return pool, nil
}
