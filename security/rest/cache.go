package rest

import (
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/go-pkgz/expirable-cache/v3"
)

const (
	internalGatewayHostName = "internal-gateway"
)

var (
	urlCacheSize = 400
	urlCacheTTL  = 5 * time.Hour
)

type empty struct{}

func getUrlCache() cache.Cache[string, empty] {
	return cache.NewCache[string, empty]().
		WithMaxKeys(urlCacheSize).
		WithLRU().
		WithTTL(urlCacheTTL)
}

func calculateCacheKey(rawUrl string) (string, error) {
	parsedUrl, err := url.Parse(rawUrl)
	if err != nil {
		return "", err
	}
	if strings.Contains(parsedUrl.Host, internalGatewayHostName) {
		return calculateCacheKeyForInternalGateway(parsedUrl), nil
	}
	return parsedUrl.Host, nil
}

func calculateCacheKeyForInternalGateway(parsedUrl *url.URL) string {
	segments := strings.Split(strings.Trim(parsedUrl.Path, "/"), "/")
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
		logger.Debug("internal-gateway url does not contain any api version; whole path will be used as a key for m2m decision cache")
	}
	key := parsedUrl.Host + "/" + strings.Join(filteredSegments, "/")
	if strings.HasPrefix(parsedUrl.Path, "/api") && serviceName != "" {
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
