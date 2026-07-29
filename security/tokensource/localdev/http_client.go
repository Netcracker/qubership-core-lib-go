package localdev

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"
)

func newHTTPClient(credentials *KubeConfigCredentials) *http.Client {
	transport := &http.Transport{
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig(credentials),
	}
	return &http.Client{
		Timeout:   httpRequestTimeout,
		Transport: transport,
	}
}

func newInsecureIdpHTTPClient() *http.Client {
	transport := &http.Transport{
		ForceAttemptHTTP2:     false,
		TLSClientConfig:       localDevInsecureTLSConfig(),
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Timeout:   httpRequestTimeout,
		Transport: transport,
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
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // NOSONAR
	}
}

func certPoolFromBytes(data []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest := data
	added := false
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block != nil {
			ok, err := addPEMCertificateToPool(pool, block)
			if err != nil {
				return nil, err
			}
			if ok {
				added = true
			}
			rest = remaining
			continue
		}
		ok, err := addDERCertificateToPool(pool, rest)
		if err != nil {
			if !added {
				return nil, fmt.Errorf("failed to parse kubeconfig CA: %w", err)
			}
			break
		}
		if ok {
			added = true
		}
		break
	}
	if !added {
		return nil, fmt.Errorf("no certificates found in kubeconfig certificate-authority-data")
	}
	return pool, nil
}

func addPEMCertificateToPool(pool *x509.CertPool, block *pem.Block) (bool, error) {
	if block.Type != "CERTIFICATE" {
		return false, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}
	pool.AddCert(cert)
	return true, nil
}

func addDERCertificateToPool(pool *x509.CertPool, data []byte) (bool, error) {
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return false, err
	}
	pool.AddCert(cert)
	return true, nil
}
