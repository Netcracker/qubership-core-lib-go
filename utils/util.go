package utils

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

const (
	CaCrt          = "ca.crt"
	TlsKey         = "tls.key"
	TlsCrt         = "tls.crt"
	DefaultTlsPath = "/etc/tls"
	TlsPathEnv     = "CERTIFICATE_FILE_PATH"
)

var cfg *config = nil
var configOnce = sync.Once{}
var logger = logging.GetLogger("tls")
var tlsEnabled = false

func IsTlsEnabled() bool {
	return tlsEnabled
}

func SetTlsEnabled(v bool) {
	tlsEnabled = v
}

type config struct {
	tlsConfig  *tls.Config
	certFile   string
	keyFile    string
	caCertFile string
}

func loadConfig() {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	cfg = &config{}
	if tlsEnabled {
		certificatePath := getOrDefaultString(TlsPathEnv, DefaultTlsPath)
		cfg.certFile = certificatePath + "/" + TlsCrt
		cfg.keyFile = certificatePath + "/" + TlsKey
		cfg.caCertFile = certificatePath + "/" + CaCrt

		// load server certificate
		serverCertificate, err := tls.LoadX509KeyPair(cfg.certFile, cfg.keyFile)
		if err != nil {
			logger.Panic("Cannot load TLS key pair from cert file=%s and key file=%s: %+v", cfg.certFile, cfg.keyFile, err)
		}

		// Read client cert file
		clientCertificates, err := ioutil.ReadFile(cfg.caCertFile)
		if err != nil {
			logger.Panic("Failed to read certificate from file=%s due to error=%+v", cfg.caCertFile, err)
		}

		// Append certificate to root CA
		if ok := rootCAs.AppendCertsFromPEM(clientCertificates); !ok {
			logger.Panic("No clientCertificates appended to trust store")
		}
		cfg.tlsConfig = &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.VerifyClientCertIfGiven,
			ClientCAs:  rootCAs,
			Certificates: []tls.Certificate{
				serverCertificate,
			},
		}
	} else {
		cfg.tlsConfig = &tls.Config{
			RootCAs: rootCAs,
		}
	}
}

func getConfig() *config {
	if cfg == nil {
		configOnce.Do(loadConfig)
	}
	return cfg
}

func GetTlsConfig() *tls.Config {
	return getConfig().tlsConfig.Clone()
}

// GetTransport returns a clone of the standard library's default transport carrying the TLS
// configuration of this package.
func GetTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = GetTlsConfig()
	return transport
}

func GetClient() *http.Client {
	return &http.Client{
		Transport: GetTransport(),
	}
}

func GetCertFile() string {
	return getConfig().certFile
}

func GetKeyFile() string {
	return getConfig().keyFile
}

func GetCaCertFile() string {
	return getConfig().caCertFile
}

func getOrDefaultString(key string, def string) string {
	//configloader may not be initialized yet, so env variables are used
	if value := os.Getenv(key); value != "" {
		return value
	}
	return def
}

func getOrDefaultBool(key string, def bool) bool {
	//configloader may not be initialized yet, so env variables are used
	value := os.Getenv(key)
	if strings.EqualFold(value, "true") {
		return true
	}
	if strings.EqualFold(value, "false") {
		return false
	}
	return def
}
