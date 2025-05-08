package allowedheaders

import (
	"context"
	"errors"
	"strings"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

const (
	HEADERS_PROPERTY           = "headers.allowed"
	ALLOWED_HEADER_CONTEX_NAME = "allowed_header"
)

var logger logging.Logger

func init() {
	logger = logging.GetLogger("allowed-headers")
}

type allowedHeaderProvider struct {
	allowedHeaders allowedHeaderSet
}

// allowedHeaderSet provides methods to work with header names in case-insensitive way
// It stores allowed headers in lowered header format for future comparison
type allowedHeaderSet map[string]struct{}

// add method is using to build initial set of headers formatted to lowered format
func (s allowedHeaderSet) add(allowedHeader string) {
	s[strings.ToLower(allowedHeader)] = struct{}{}
}

// isAllowedHeader using to check if header name is allowed by comparison lowered format
func (s allowedHeaderSet) isAllowedHeader(header string) bool {
	_, ok := s[strings.ToLower(header)]
	return ok
}

func NewAllowedHeaderProvider() allowedHeaderProvider {
	allowedHeadersRaw := strings.Split(strings.ReplaceAll(configloader.GetOrDefaultString(HEADERS_PROPERTY, ""), " ", ""), ",")
	allowedHeaders := allowedHeaderSet{}
	for _, header := range allowedHeadersRaw {
		allowedHeaders.add(header)
	}
	return allowedHeaderProvider{
		allowedHeaders: allowedHeaders,
	}
}

func (allowedHeaderProvider allowedHeaderProvider) InitLevel() int {
	return 0
}

func (allowedHeaderProvider allowedHeaderProvider) ContextName() string {
	return ALLOWED_HEADER_CONTEX_NAME
}

func (allowedHeaderProvider allowedHeaderProvider) Provide(ctx context.Context, incomingData map[string]interface{}) context.Context {
	var allowedRequestHeaders = make(map[string]string)

	for headerName, value := range incomingData {
		if allowedHeaderProvider.allowedHeaders.isAllowedHeader(headerName) {
			allowedRequestHeaders[headerName] = value.(string)
			logger.Debug("context object=" + headerName + " provided to context.Context")
		}
	}

	return context.WithValue(ctx, ALLOWED_HEADER_CONTEX_NAME, NewAllowedHeaderContextObject(allowedRequestHeaders))
}

func (allowedHeaderProvider allowedHeaderProvider) Set(ctx context.Context, allowedHeadersObject interface{}) (context.Context, error) {
	allowedHeaders, success := allowedHeadersObject.(allowedHeaderContextObject)
	if !success {
		return ctx, errors.New("incorrect type to set allowedHeaders")
	}
	var allowedRequestHeaders = make(map[string]string)
	for headerName, value := range allowedHeaders.header {
		if allowedHeaderProvider.allowedHeaders.isAllowedHeader(headerName) {
			allowedRequestHeaders[headerName] = value
			logger.Debug("context object=" + headerName + " set to context.Context")
		}
	}
	return context.WithValue(ctx, ALLOWED_HEADER_CONTEX_NAME, NewAllowedHeaderContextObject(allowedRequestHeaders)), nil
}

func (allowedHeaderProvider allowedHeaderProvider) Get(ctx context.Context) interface{} {
	return ctx.Value(ALLOWED_HEADER_CONTEX_NAME)
}
