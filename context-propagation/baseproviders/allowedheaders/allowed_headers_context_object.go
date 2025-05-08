package allowedheaders

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)

type allowedHeaderContextObject struct {
	header map[string]string
}

func NewAllowedHeaderContextObject(headers map[string]string) allowedHeaderContextObject {
	return allowedHeaderContextObject{header: headers}
}

// Deprecated: GetHeaders returns raw map of headers with values. Keys in map are case-sensitive.
// Use GetHeader to get header value in case-insentitive way
// Use GetHeaderNames to get list of available custom headers in context
func (allowedHeaderContextObject allowedHeaderContextObject) GetHeaders() map[string]string {
	return allowedHeaderContextObject.header
}

// GetHeader method returns value by header name and true if exists
// It works in case-insensitive way
func (allowedHeaderContextObject allowedHeaderContextObject) GetHeader(header string) (string, bool) {
	for headerName, value := range allowedHeaderContextObject.header {
		if strings.ToLower(headerName) == strings.ToLower(header) {
			return value, true
		}
	}
	return "", false
}

// GetHeaderNames method returns slice of available headers in context
func (allowedHeaderContextObject allowedHeaderContextObject) GetHeaderNames() []string {
	headerNames := make([]string, 0, len(allowedHeaderContextObject.header))
	for headerName := range allowedHeaderContextObject.header {
		headerNames = append(headerNames, headerName)
	}
	return headerNames
}

func (allowedHeaderContextObject allowedHeaderContextObject) GetLogValue() string {
	l := []string{}
	for key, value := range allowedHeaderContextObject.header {
		l = append(l, fmt.Sprintf("'%s':'%s'", key, value))
	}
	return strings.Join(l, ", ")
}

func (allowedHeaderContextObject allowedHeaderContextObject) Serialize() (map[string]string, error) {
	if allowedHeaderContextObject.header == nil || len(allowedHeaderContextObject.header) == 0 {
		return nil, nil
	}
	return allowedHeaderContextObject.header, nil
}

func Of(ctx context.Context) (*allowedHeaderContextObject, error) {
	var contextObject allowedHeaderContextObject
	contextProvider, err := ctxmanager.GetProvider(ALLOWED_HEADER_CONTEX_NAME)
	if err != nil {
		return nil, err
	}
	abstractContextObject := contextProvider.Get(ctx)
	if abstractContextObject == nil {
		return nil, errors.New("allowedHeaders context object is null")
	}
	contextObject = (abstractContextObject).(allowedHeaderContextObject)

	return &contextObject, nil
}
