package tokensource

import (
	"context"
	"testing"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileTokenSource(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()
	var err error
	var ok bool

	audienceTokensStorage, err := test.NewAudienceTokensStorage(t.TempDir())
	require.NoError(t, err)
	serviceAccountTokenStorage, err := test.NewServiceAccountTokenStorage(t.TempDir())
	require.NoError(t, err)

	DefaultAudienceTokensDir = audienceTokensStorage.AudienceTokensDir
	DefaultServiceAccountDir = serviceAccountTokenStorage.ServiceAccountTokenDir

	netcrackerTokenInitialValue := "netcracker_token_initial_value"
	err, ok = audienceTokensStorage.SaveTokenValue(AudienceNetcracker, netcrackerTokenInitialValue)
	assert.True(t, ok)
	require.NoError(t, err)

	dbaasTokenInitialValue := "dbaas_token_initial_value"
	err, ok = audienceTokensStorage.SaveTokenValue(AudienceDBaaS, dbaasTokenInitialValue)
	assert.True(t, ok)
	require.NoError(t, err)

	serviceAccountTokenInitialValue := "service_account_token_initial_value"
	err, ok = serviceAccountTokenStorage.SaveTokenValue(serviceAccountTokenInitialValue)
	assert.True(t, ok)
	require.NoError(t, err)

	token, err := GetAudienceToken(ctx, AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, netcrackerTokenInitialValue, token)

	token, err = GetAudienceToken(ctx, AudienceDBaaS)
	require.NoError(t, err)
	assert.Equal(t, dbaasTokenInitialValue, token)

	token, err = GetServiceAccountToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, serviceAccountTokenInitialValue, token)

	netcrackerTokenSecondValue := "netcracker_token_second_value"
	err, ok = audienceTokensStorage.SaveTokenValue(AudienceNetcracker, netcrackerTokenSecondValue)
	assert.True(t, ok)
	require.NoError(t, err)

	token, err = GetAudienceToken(ctx, AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, netcrackerTokenSecondValue, token)

	dbaasTokenSecondValue := "dbaas_token_second_value"
	err, ok = audienceTokensStorage.SaveTokenValue(AudienceDBaaS, dbaasTokenSecondValue)
	assert.True(t, ok)
	require.NoError(t, err)

	token, err = GetAudienceToken(ctx, AudienceDBaaS)
	require.NoError(t, err)
	assert.Equal(t, dbaasTokenSecondValue, token)

	serviceAccountTokenSecondValue := "service_account_token_second_value"
	err, ok = serviceAccountTokenStorage.SaveTokenValue(serviceAccountTokenSecondValue)
	assert.True(t, ok)
	require.NoError(t, err)

	token, err = GetServiceAccountToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, serviceAccountTokenSecondValue, token)

	audienceTokensWatcher.Store(nil)
	serviceAccountTokenWatcher.Store(nil)
}

func TestGetAudienceTokenEmptyAudience(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()
	var err error

	_, err = GetAudienceToken(ctx, "")
	assert.ErrorContains(t, err, "audience is empty")
}
