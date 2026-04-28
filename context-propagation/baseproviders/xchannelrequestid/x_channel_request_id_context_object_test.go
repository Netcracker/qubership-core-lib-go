package xchannelrequestid

import (
	"context"
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
	"github.com/stretchr/testify/assert"
)

const xChannelRequestIdValue = "42"

func init() {
	ctxmanager.Register([]ctxmanager.ContextProvider{XChannelRequestIdProvider{}})
}

func TestChannelRequestIdSerializableCtx(t *testing.T) {
	incomingHeaders := getIncomingRequestHeaders()
	ctx := ctxmanager.InitContext(context.Background(), incomingHeaders)
	contextData, err := ctxmanager.GetContextObject(ctx, X_CHANNEL_REQUEST_ID_COTEXT_NAME)
	assert.NotNil(t, contextData)
	assert.Nil(t, err)
	requestId, _ := Of(ctx)
	assert.Equal(t, xChannelRequestIdValue, requestId.channelRequestId)
	outgoingData, _ := ctxmanager.GetSerializableContextData(ctx)
	assert.Equal(t, xChannelRequestIdValue, outgoingData[X_CHANNEL_REQUEST_ID_HEADER_NAME])
}

func TestChannelRequestIdIncomingResponsePropagatableCtx(t *testing.T) {
	incomingHeaders := getIncomingRequestHeaders()
	ctx := ctxmanager.InitContext(context.Background(), incomingHeaders)
	contextData, err := ctxmanager.GetContextObject(ctx, X_CHANNEL_REQUEST_ID_COTEXT_NAME)
	assert.NotNil(t, contextData)
	assert.Nil(t, err)
	requestId, _ := Of(ctx)
	assert.Equal(t, xChannelRequestIdValue, requestId.channelRequestId)
	responseContextData, _ := ctxmanager.GetResponsePropagatableContextData(ctx)
	assert.Equal(t, xChannelRequestIdValue, responseContextData[X_CHANNEL_REQUEST_ID_HEADER_NAME])
}

func TestOfChannelRequestIdContext(t *testing.T) {
	ctx := ctxmanager.InitContext(context.Background(), getIncomingRequestHeaders())
	requestId, _ := Of(ctx)
	assert.Equal(t, xChannelRequestIdValue, requestId.channelRequestId)
}

func TestSetChannelRequestIdProvider(t *testing.T) {
	ctx := ctxmanager.InitContext(context.Background(), getIncomingRequestHeaders())

	xRequestId, _ := Of(ctx)
	assert.Equal(t, xChannelRequestIdValue, xRequestId.channelRequestId)

	var err error
	ctx, err = ctxmanager.SetContextObject(ctx, X_CHANNEL_REQUEST_ID_COTEXT_NAME, NewXChannelRequestIdContextObject("24"))
	assert.Nil(t, err)
	secondXRequestId, _ := Of(ctx)
	assert.Equal(t, "24", secondXRequestId.channelRequestId)
}

func TestErrorSetAcceptLanguageProvider(t *testing.T) {
	provider, _ := ctxmanager.GetProvider(X_CHANNEL_REQUEST_ID_COTEXT_NAME)
	_, err := provider.Set(context.Background(), "wrong type")
	assert.NotNil(t, err)
}

func TestContextName(t *testing.T) {
	assert.Equal(t, XChannelRequestIdProvider{}.ContextName(), X_CHANNEL_REQUEST_ID_COTEXT_NAME)
}

func getIncomingRequestHeaders() map[string]interface{} {
	return map[string]interface{}{X_CHANNEL_REQUEST_ID_COTEXT_NAME: xChannelRequestIdValue}
}

func TestGetLogValue(t *testing.T) {
	ctx := ctxmanager.InitContext(context.Background(), getIncomingRequestHeaders())

	xRequestId, _ := Of(ctx)
	assert.Equal(t, xChannelRequestIdValue, xRequestId.channelRequestId)
	assert.Equal(t, xChannelRequestIdValue, xRequestId.GetLogValue())
}
