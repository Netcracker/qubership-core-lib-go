package xrequestid

import (
	"context"
	"errors"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

const X_REQUEST_ID_COTEXT_NAME = "X-Request-Id"

type XRequestIdProvider struct {
}

var logger logging.Logger

func init() {
	logger = logging.GetLogger("x-request-id")
}

func (xRequestIdProvider XRequestIdProvider) InitLevel() int {
	return 0
}

func (xRequestIdProvider XRequestIdProvider) ContextName() string {
	return X_REQUEST_ID_COTEXT_NAME
}

func (xRequestIdProvider XRequestIdProvider) Provide(ctx context.Context, incomingData map[string]interface{}) context.Context {
	headerValue := ""
	if incomingData[X_REQUEST_ID_HEADER_NAME] != nil {
		headerValue = incomingData[X_REQUEST_ID_HEADER_NAME].(string)
	}
	logger.Debug("context object=%s provided to context.Context", X_REQUEST_ID_COTEXT_NAME)
	return context.WithValue(ctx, X_REQUEST_ID_COTEXT_NAME, NewXRequestIdContextObject(headerValue))
}

func (xRequestIdProvider XRequestIdProvider) Set(ctx context.Context, xRequestIdObject interface{}) (context.Context, error) {
	xRequestId, success := xRequestIdObject.(*xRequestIdContextObject)
	if !success {
		return ctx, errors.New("incorrect type to set xRequestId")
	}
	logger.Debug("context object=%s set to context.Context", X_REQUEST_ID_HEADER_NAME)
	return context.WithValue(ctx, X_REQUEST_ID_HEADER_NAME, xRequestId), nil
}

func (xRequestIdProvider XRequestIdProvider) Get(ctx context.Context) interface{} {
	return ctx.Value(X_REQUEST_ID_HEADER_NAME)
}
