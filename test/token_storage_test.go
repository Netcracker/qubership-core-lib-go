package test

import (
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceAccountToken(t *testing.T) {
	ctx := t.Context()

	storage, err := NewServiceAccountTokenStorage(t.TempDir())
	require.NoError(t, err)
	tokensource.DefaultServiceAccountDir = storage.ServiceAccountTokenDir
	logger.Infof("service account token dir is %s", storage.ServiceAccountTokenDir)

	serviceAccountTokenInitialValue := "service_account_token_initial_value"
	err = storage.SaveTokenValue(serviceAccountTokenInitialValue)
	require.NoError(t, err)

	token, err := tokensource.GetServiceAccountToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, serviceAccountTokenInitialValue, token)

	serviceAccountTokenSecondValue := "service_account_token_second_value"
	err = storage.SaveTokenValue(serviceAccountTokenSecondValue)
	require.NoError(t, err)

	token, err = tokensource.GetServiceAccountToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, serviceAccountTokenSecondValue, token)

	_ = storage.Clear()
	tokensource.OnCloseServiceAccountTokenWatcher()
}

func TestNoServiceAccountToken(t *testing.T) {
	ctx := t.Context()

	storage, err := NewServiceAccountTokenStorage(t.TempDir())
	require.NoError(t, err)
	tokensource.DefaultServiceAccountDir = storage.ServiceAccountTokenDir
	logger.Infof("service account token dir is %s", storage.ServiceAccountTokenDir)

	err = storage.DeleteTokenFile()
	require.NoError(t, err)

	_, err = tokensource.GetServiceAccountToken(ctx)
	assert.ErrorContains(t, err, "failed to get token default kubernetes service account token: failed to read token at path")

	err = storage.SaveTokenValue("value")
	require.NoError(t, err)

	token, err := tokensource.GetServiceAccountToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, "value", token)

	err = storage.DeleteTokenFile()
	require.NoError(t, err)

	_, err = tokensource.GetServiceAccountToken(ctx)
	assert.ErrorContains(t, err, "failed to get token default kubernetes service account token: failed to read token at path")

	_ = storage.Clear()
	tokensource.OnCloseServiceAccountTokenWatcher()
}

func TestNoServiceAccountTokenDir(t *testing.T) {
	ctx := t.Context()

	storage, err := NewServiceAccountTokenStorage(t.TempDir())
	require.NoError(t, err)
	tokensource.DefaultServiceAccountDir = storage.ServiceAccountTokenDir
	logger.Infof("service account token dir is %s", storage.ServiceAccountTokenDir)

	err = storage.Clear()
	require.NoError(t, err)

	_, err = tokensource.GetServiceAccountToken(ctx)
	assert.ErrorContains(t, err, "failed to create token watcher: failed to add path")

	_ = storage.Clear()
	tokensource.OnCloseServiceAccountTokenWatcher()
}

func TestAudienceTokens(t *testing.T) {
	ctx := t.Context()

	storage, err := NewAudienceTokensStorage(t.TempDir())
	require.NoError(t, err)
	tokensource.DefaultAudienceTokensDir = storage.AudienceTokensDir
	logger.Infof("audience tokens dir is %s", storage.AudienceTokensDir)

	netcrackerTokenInitialValue := "netcracker_token_initial_value"
	err = storage.SaveTokenValue(tokensource.AudienceNetcracker, netcrackerTokenInitialValue)
	require.NoError(t, err)

	dbaasTokenInitialValue := "dbaas_token_initial_value"
	err = storage.SaveTokenValue(tokensource.AudienceDBaaS, dbaasTokenInitialValue)
	require.NoError(t, err)

	token, err := tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, netcrackerTokenInitialValue, token)

	token, err = tokensource.GetAudienceToken(ctx, tokensource.AudienceDBaaS)
	require.NoError(t, err)
	assert.Equal(t, dbaasTokenInitialValue, token)

	netcrackerTokenSecondValue := "netcracker_token_second_value"
	err = storage.SaveTokenValue(tokensource.AudienceNetcracker, netcrackerTokenSecondValue)
	require.NoError(t, err)

	token, err = tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, netcrackerTokenSecondValue, token)

	dbaasTokenSecondValue := "dbaas_token_second_value"
	err = storage.SaveTokenValue(tokensource.AudienceDBaaS, dbaasTokenSecondValue)
	require.NoError(t, err)

	token, err = tokensource.GetAudienceToken(ctx, tokensource.AudienceDBaaS)
	require.NoError(t, err)
	assert.Equal(t, dbaasTokenSecondValue, token)

	_ = storage.Clear()
	tokensource.OnCloseAudienceTokensWatcher()
}

func TestNoAudienceToken(t *testing.T) {
	ctx := t.Context()

	storage, err := NewAudienceTokensStorage(t.TempDir())
	require.NoError(t, err)
	tokensource.DefaultAudienceTokensDir = storage.AudienceTokensDir
	logger.Infof("audience tokens dir is %s", storage.AudienceTokensDir)

	_, err = tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
	assert.ErrorContains(t, err, "token with audience netcracker was not found")

	err = storage.SaveTokenValue(tokensource.AudienceNetcracker, "value")
	require.NoError(t, err)

	token, err := tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, "value", token)

	err = storage.DeleteTokenFile(tokensource.AudienceNetcracker)
	require.NoError(t, err)

	_, err = tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
	assert.ErrorContains(t, err, "failed to get token by audience: netcracker: failed to read token at path")

	_ = storage.Clear()
	tokensource.OnCloseAudienceTokensWatcher()
}

func TestNoAudienceTokensDir(t *testing.T) {
	ctx := t.Context()

	storage, err := NewAudienceTokensStorage(t.TempDir())
	require.NoError(t, err)
	tokensource.DefaultAudienceTokensDir = storage.AudienceTokensDir
	logger.Infof("audience tokens dir is %s", storage.AudienceTokensDir)

	err = storage.Clear()
	require.NoError(t, err)

	_, err = tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
	assert.ErrorContains(t, err, "failed to create token watcher: failed to refresh tokens cache: failed to get dir entries from tokenDir")

	_ = storage.Clear()
	tokensource.OnCloseAudienceTokensWatcher()
}
