package xrequestid

import (
	"context"
	"errors"
	"fmt"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
	"math/rand"
	"time"
)

const X_REQUEST_ID_HEADER_NAME = "X-Request-Id"

type xRequestIdContextObject struct {
	requestId string
}

// This interface is internal and not support backward compatibility
type XRequestId interface {
	GetRequestId() string
}

func NewXRequestIdContextObject(headerValues string) *xRequestIdContextObject {
	if headerValues == "" {
		headerValues = generateRequestId()
	}
	return &xRequestIdContextObject{headerValues}
}

func (xRequestIdContextObject xRequestIdContextObject) Serialize() (map[string]string, error) {
	if xRequestIdContextObject.requestId == "" {
		return nil, nil
	}
	return map[string]string{X_REQUEST_ID_HEADER_NAME: xRequestIdContextObject.requestId}, nil
}

func (xRequestIdContextObject xRequestIdContextObject) Propagate() (map[string]string, error) {
	return xRequestIdContextObject.Serialize()
}

func (xRequestIdContextObject xRequestIdContextObject) GetRequestId() string {
	return ""
}

func (xRequestIdContextObject xRequestIdContextObject) GetLogValue() string {
	return xRequestIdContextObject.requestId
}

func Of(ctx context.Context) (*xRequestIdContextObject, error) {
	contextProvider, err := ctxmanager.GetProvider(X_REQUEST_ID_COTEXT_NAME)
	if err != nil {
		return nil, err
	}
	abstractContextObject := contextProvider.Get(ctx)
	if abstractContextObject == nil {
		return nil, errors.New("xRequestId context object is null")
	}
	contextObject := (abstractContextObject).(*xRequestIdContextObject)
	return contextObject, nil
}

func generateRequestId() string {
	return fmt.Sprintf("%d", time.Now().Nanosecond()) + fmt.Sprintf("%f", rand.Float64())
}
