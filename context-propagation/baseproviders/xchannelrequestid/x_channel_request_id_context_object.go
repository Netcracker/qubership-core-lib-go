package xchannelrequestid

import (
	"context"
	"errors"
	"fmt"

	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)

const X_CHANNEL_REQUEST_ID_HEADER_NAME = "X-Channel-Request-Id"

type XChannelRequestIdContextObject struct {
	channelRequestId string
}

func NewXChannelRequestIdContextObject(headerValues string) *XChannelRequestIdContextObject {
	return &XChannelRequestIdContextObject{headerValues}
}

func (xChannelRequestIdContextObject XChannelRequestIdContextObject) Serialize() (map[string]string, error) {
	if xChannelRequestIdContextObject.channelRequestId == "" {
		return nil, nil
	}
	return map[string]string{X_CHANNEL_REQUEST_ID_HEADER_NAME: xChannelRequestIdContextObject.channelRequestId}, nil
}

func (xChannelRequestIdContextObject XChannelRequestIdContextObject) Propagate() (map[string]string, error) {
	return xChannelRequestIdContextObject.Serialize()
}

func (xChannelRequestIdContextObject XChannelRequestIdContextObject) GetLogValue() string {
	return xChannelRequestIdContextObject.channelRequestId
}

func Of(ctx context.Context) (*XChannelRequestIdContextObject, error) {
	contextProvider, err := ctxmanager.GetProvider(X_CHANNEL_REQUEST_ID_HEADER_NAME)
	if err != nil {
		return nil, err
	}
	abstractContextObject := contextProvider.Get(ctx)
	if abstractContextObject == nil {
		return nil, errors.New("xChannelRequestId context object is null")
	}
	contextObject, ok := abstractContextObject.(*XChannelRequestIdContextObject)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T for xChannelRequestId context object", abstractContextObject)
	}
	return contextObject, nil
}
