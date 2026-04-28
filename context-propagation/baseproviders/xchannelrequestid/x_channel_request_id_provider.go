package xchannelrequestid

import (
	"context"
	"errors"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

const X_CHANNEL_REQUEST_ID_CONTEXT_NAME = "X-Channel-Request-Id"

type XChannelRequestIdProvider struct {
}

var logger logging.Logger

func init() {
	logger = logging.GetLogger("x-channel-request-id")
}

func (xChannelRequestIdProvider XChannelRequestIdProvider) InitLevel() int {
	return 0
}

func (xChannelRequestIdProvider XChannelRequestIdProvider) ContextName() string {
	return X_CHANNEL_REQUEST_ID_CONTEXT_NAME
}

func (xChannelRequestIdProvider XChannelRequestIdProvider) Provide(ctx context.Context, incomingData map[string]interface{}) context.Context {
	headerValue := ""
	if incomingData[X_CHANNEL_REQUEST_ID_CONTEXT_NAME] != nil {
		headerValue = incomingData[X_CHANNEL_REQUEST_ID_CONTEXT_NAME].(string)
	}
	logger.Debug("context object=%s provided to context.Context", X_CHANNEL_REQUEST_ID_CONTEXT_NAME)
	return context.WithValue(ctx, X_CHANNEL_REQUEST_ID_CONTEXT_NAME, NewXChannelRequestIdContextObject(headerValue))
}

func (xChannelRequestIdProvider XChannelRequestIdProvider) Set(ctx context.Context, xChannelRequestIdObject interface{}) (context.Context, error) {
	xChannelRequestId, success := xChannelRequestIdObject.(*XChannelRequestIdContextObject)
	if !success {
		return ctx, errors.New("incorrect type to set xChannelRequestId")
	}
	logger.Debug("context object=%s set to context.Context", X_CHANNEL_REQUEST_ID_CONTEXT_NAME)
	return context.WithValue(ctx, X_CHANNEL_REQUEST_ID_CONTEXT_NAME, xChannelRequestId), nil
}

func (xChannelRequestIdProvider XChannelRequestIdProvider) Get(ctx context.Context) interface{} {
	return ctx.Value(X_CHANNEL_REQUEST_ID_CONTEXT_NAME)
}
