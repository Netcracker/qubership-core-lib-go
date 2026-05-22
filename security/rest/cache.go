package rest

import (
	"net/url"
	"strings"
	"time"
	"unicode"

	cache "github.com/go-pkgz/expirable-cache/v3"
)

var (
	urlCacheSize = 400
	urlCacheTTL  = 5 * time.Hour
)

type empty struct{}

func newUrlCache() cache.Cache[string, empty] {
	return cache.NewCache[string, empty]().
		WithMaxKeys(urlCacheSize).
		WithLRU().
		WithTTL(urlCacheTTL)
}

func calculateCacheKey(internalGatewayHostName, rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if parsedURL.Hostname() == internalGatewayHostName {
		return calculateCacheKeyForInternalGateway(parsedURL), nil
	}
	return parsedURL.Host, nil
}

func calculateCacheKeyForInternalGateway(parsedURL *url.URL) string {
	segments := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")
	var filteredSegments []string
	var version string
	var serviceName string

	for _, segment := range segments {
		if version != "" {
			serviceName = segment
			break
		}
		filteredSegments = append(filteredSegments, segment)
		if isVersion(segment) {
			version = segment
		}
	}

	if version == "" {
		logger.Debug("internal-gateway-service url does not contain any api version; whole path will be used as a key for m2m decision cache")
	}
	key := parsedURL.Host + "/" + strings.Join(filteredSegments, "/")
	if strings.HasPrefix(parsedURL.Path, "/api") && serviceName != "" {
		key = key + "/" + serviceName
	}
	return key
}

func isVersion(segment string) bool {
	if len(segment) < 2 {
		return false
	}
	if segment[0] != 'v' {
		return false
	}
	for _, character := range segment[1:] {
		if !unicode.IsDigit(character) {
			return false
		}
	}
	return true
}
