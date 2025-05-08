package allowedheaders

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)

const CUSTOM_HEADER_2 = "Custom-header-2"
const CUSTOM_HEADER = "Custom-header-1"
const CUSTOM_HEADER_VALUE = "custom_value"
const CUSTOM_HEADER_VALUE_2 = "custom_value_2"

func init() {
	_ = os.Setenv(HEADERS_PROPERTY, CUSTOM_HEADER+", "+CUSTOM_HEADER_2)
	configloader.Init(configloader.EnvPropertySource())
	ctxmanager.Register([]ctxmanager.ContextProvider{NewAllowedHeaderProvider()})
}

func TestAllowedHeaderCtx(t *testing.T) {
	ctx := ctxmanager.InitContext(context.Background(), getIncomingRequestHeaders())
	contextData, err := ctxmanager.GetContextObject(ctx, ALLOWED_HEADER_CONTEX_NAME)
	assert.NotNil(t, contextData)
	assert.Nil(t, err)
	allowedHeaders, err := Of(ctx)
	assert.NoError(t, err)

	header, exists := allowedHeaders.GetHeader(CUSTOM_HEADER)
	assert.True(t, exists)
	assert.Equal(t, CUSTOM_HEADER_VALUE, header)
	header, exists = allowedHeaders.GetHeader(CUSTOM_HEADER_2)
	assert.True(t, exists)
	assert.Equal(t, CUSTOM_HEADER_VALUE_2, header)
	_ = os.Unsetenv("headers.allowed")
}

func TestWrongAllowedHeaderCtx(t *testing.T) {
	ctx := ctxmanager.InitContext(context.Background(), getIncomingRequestHeaders())
	contextData, err := ctxmanager.GetContextObject(ctx, ALLOWED_HEADER_CONTEX_NAME)
	assert.NotNil(t, contextData)
	assert.Nil(t, err)
	allowedHeaders, _ := Of(ctx)

	_, headerExists := allowedHeaders.GetHeader("SomeContext")
	assert.False(t, headerExists)
}

func TestSetAllowedHeadersProvider(t *testing.T) {
	ctx := ctxmanager.InitContext(context.Background(), getIncomingRequestHeaders())

	allowedHeaders, _ := Of(ctx)

	header, exists := allowedHeaders.GetHeader(CUSTOM_HEADER)
	assert.True(t, exists)
	assert.Equal(t, CUSTOM_HEADER_VALUE, header)

	var err error
	ctx, err = ctxmanager.SetContextObject(ctx, ALLOWED_HEADER_CONTEX_NAME, NewAllowedHeaderContextObject(map[string]string{CUSTOM_HEADER: "new_custom_value"}))
	assert.Nil(t, err)
	secondAllowedHeaders, _ := Of(ctx)

	header, exists = secondAllowedHeaders.GetHeader(CUSTOM_HEADER)
	assert.True(t, exists)
	assert.Equal(t, "new_custom_value", header)

	_, exists = secondAllowedHeaders.GetHeader(CUSTOM_HEADER_2)
	assert.False(t, exists)
}

func TestAllowedHeadersCaseInsensitiveProvider(t *testing.T) {
	ctx := ctxmanager.InitContext(context.Background(), getIncomingRequestHeaders())

	allowedHeaders, _ := Of(ctx)

	header, exists := allowedHeaders.GetHeader(strings.ToLower(CUSTOM_HEADER))
	assert.True(t, exists)
	assert.Equal(t, CUSTOM_HEADER_VALUE, header)
	// check that header key stayed as-is
	assert.Equal(t, CUSTOM_HEADER_VALUE, allowedHeaders.header[CUSTOM_HEADER])

	header, exists = allowedHeaders.GetHeader(strings.ToUpper(CUSTOM_HEADER_2))
	assert.True(t, exists)
	assert.Equal(t, CUSTOM_HEADER_VALUE_2, header)
	// check that header key stayed as-is
	assert.Equal(t, CUSTOM_HEADER_VALUE_2, allowedHeaders.header[CUSTOM_HEADER_2])
}

func TestAllowedHeadersProviderSerialization(t *testing.T) {
	ctx := ctxmanager.InitContext(context.Background(), getIncomingRequestHeaders())

	allowedHeaders, err := Of(ctx)
	assert.NoError(t, err)

	serialized, err := allowedHeaders.Serialize()
	assert.NoError(t, err)
	assert.Equal(t, CUSTOM_HEADER_VALUE, serialized[CUSTOM_HEADER])
	assert.Equal(t, CUSTOM_HEADER_VALUE_2, serialized[CUSTOM_HEADER_2])
}

func TestAllowedHeadersProviderListHeaderNames(t *testing.T) {
	ctx := ctxmanager.InitContext(context.Background(), getIncomingRequestHeaders())

	allowedHeaders, err := Of(ctx)
	assert.NoError(t, err)

	headers := allowedHeaders.GetHeaderNames()
	assert.Len(t, headers, 2)
	assert.Contains(t, headers, CUSTOM_HEADER)
	assert.Contains(t, headers, CUSTOM_HEADER_2)
}

func TestErrorSetAcceptLanguageProvider(t *testing.T) {
	provider, _ := ctxmanager.GetProvider(ALLOWED_HEADER_CONTEX_NAME)
	_, err := provider.Set(context.Background(), "wrong type")
	assert.NotNil(t, err)
}

func TestContextName(t *testing.T) {
	assert.Equal(t, allowedHeaderProvider{}.ContextName(), ALLOWED_HEADER_CONTEX_NAME)
}

func getIncomingRequestHeaders() map[string]interface{} {
	return map[string]interface{}{
		CUSTOM_HEADER:   CUSTOM_HEADER_VALUE,
		CUSTOM_HEADER_2: CUSTOM_HEADER_VALUE_2}
}

func TestGetLogValue(t *testing.T) {
	ctx := ctxmanager.InitContext(context.Background(), getIncomingRequestHeaders())

	allowedHeaders, _ := Of(ctx)

	expectedHeader1 := fmt.Sprintf("'%s':'%s'", CUSTOM_HEADER, CUSTOM_HEADER_VALUE)
	expectedHeader2 := fmt.Sprintf("'%s':'%s'", CUSTOM_HEADER_2, CUSTOM_HEADER_VALUE_2)

	actualHeaders := allowedHeaders.GetLogValue()
	assert.Contains(t, actualHeaders, expectedHeader1)
	assert.Contains(t, actualHeaders, expectedHeader2)
}
