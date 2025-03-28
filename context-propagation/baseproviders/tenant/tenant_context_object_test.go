package tenant

import (
	"context"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
	"github.com/stretchr/testify/assert"
	"net/textproto"
	"testing"
)

var (
	tenant  = "test-tenant"
	headers = map[string]interface{}{
		textproto.CanonicalMIMEHeaderKey(TenantHeader): tenant,
	}
)

func init() {
	ctxmanager.Register([]ctxmanager.ContextProvider{TenantProvider{}})
}

func TestTenantProvider_Provide(t *testing.T) {
	ctx := ctxmanager.InitContext(context.Background(), headers)
	ctxObj, err := Of(ctx)
	assert.Nil(t, err)
	assert.Equal(t, tenant, ctxObj.GetTenant())
}

func TestTenantProvider_Set(t *testing.T) {
	ctx, err := TenantProvider{}.Set(context.Background(), tenant)
	assert.Nil(t, err)
	ctxObj, err := Of(ctx)
	assert.Nil(t, err)
	assert.Equal(t, tenant, ctxObj.GetTenant())
}

func TestTenantContextObject_Serialize(t *testing.T) {
	ctx := ctxmanager.InitContext(context.Background(), headers)
	serializedData, err := ctxmanager.GetSerializableContextData(ctx)
	assert.Nil(t, err)
	assert.Equal(t, tenant, serializedData[TenantHeader])
}
