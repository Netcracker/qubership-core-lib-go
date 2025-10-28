package test

import (
	"context"
	"testing"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAudienceToken(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()
	var err error
	var ok bool

	audienceTokensStorage, err := NewAudienceTokensStorage(t.TempDir())
	require.NoError(t, err)

	tokensource.DefaultAudienceTokensDir = audienceTokensStorage.AudienceTokensDir

	netcrackerTokenInitialValue := "netcracker_token_initial_value"
	err, ok = audienceTokensStorage.SaveTokenValue(tokensource.AudienceNetcracker, netcrackerTokenInitialValue)
	assert.True(t, ok)
	require.NoError(t, err)

	token, err := tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, netcrackerTokenInitialValue, token)

	err, ok = audienceTokensStorage.DeleteTokenFile(tokensource.AudienceNetcracker)
	assert.True(t, ok)
	assert.NoError(t, err)

	token, err = tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
	assert.ErrorContains(t, err, "failed to get token by audience: netcracker: failed to read token at path")

	err, ok = audienceTokensStorage.SaveTokenValue(tokensource.AudienceNetcracker, netcrackerTokenInitialValue)
	assert.True(t, ok)
	require.NoError(t, err)

	token, err = tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, netcrackerTokenInitialValue, token)
}

func TestServiceAccountToken(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()
	var err error
	var ok bool

	serviceAccountTokenStorage, err := NewServiceAccountTokenStorage(t.TempDir())
	require.NoError(t, err)

	tokensource.DefaultServiceAccountDir = serviceAccountTokenStorage.ServiceAccountTokenDir

	serviceAccountTokenInitialValue := "service_account_token_initial_value"
	err, ok = serviceAccountTokenStorage.SaveTokenValue(serviceAccountTokenInitialValue)
	assert.True(t, ok)
	require.NoError(t, err)

	token, err := tokensource.GetServiceAccountToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, serviceAccountTokenInitialValue, token)

	err, ok = serviceAccountTokenStorage.DeleteTokenFile()
	assert.True(t, ok)
	assert.NoError(t, err)

	token, err = tokensource.GetServiceAccountToken(ctx)
	assert.ErrorContains(t, err, "failed to get token default kubernetes service account token: failed to read token at path")

	err, ok = serviceAccountTokenStorage.SaveTokenValue(serviceAccountTokenInitialValue)
	assert.True(t, ok)
	require.NoError(t, err)

	token, err = tokensource.GetServiceAccountToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, serviceAccountTokenInitialValue, token)
}
