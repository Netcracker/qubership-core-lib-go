package tokensource

import (
	"context"
	"testing"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceAccountToken(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); time.Sleep(time.Second) }()

	storage, err := test.NewServiceAccountTokenStorage(t.TempDir())
	require.NoError(t, err)
	DefaultServiceAccountDir = storage.ServiceAccountTokenDir
	logger.Infof("service account token dir is %s", storage.ServiceAccountTokenDir)

	serviceAccountTokenInitialValue := "service_account_token_initial_value"
	err = storage.SaveTokenValue(serviceAccountTokenInitialValue)
	require.NoError(t, err)

	token, err := GetServiceAccountToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, serviceAccountTokenInitialValue, token)

	serviceAccountTokenSecondValue := "service_account_token_second_value"
	err = storage.SaveTokenValue(serviceAccountTokenSecondValue)
	require.NoError(t, err)

	token, err = GetServiceAccountToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, serviceAccountTokenSecondValue, token)

	_ = storage.Clear()
}

func TestNoServiceAccountToken(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); time.Sleep(time.Second) }()

	storage, err := test.NewServiceAccountTokenStorage(t.TempDir())
	require.NoError(t, err)
	DefaultServiceAccountDir = storage.ServiceAccountTokenDir
	logger.Infof("service account token dir is %s", storage.ServiceAccountTokenDir)

	err = storage.DeleteTokenFile()
	require.NoError(t, err)

	_, err = GetServiceAccountToken(ctx)
	assert.ErrorContains(t, err, "failed to get token default kubernetes service account token: failed to read token at path")

	err = storage.SaveTokenValue("value")
	require.NoError(t, err)

	token, err := GetServiceAccountToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, "value", token)

	err = storage.DeleteTokenFile()
	require.NoError(t, err)

	_, err = GetServiceAccountToken(ctx)
	assert.ErrorContains(t, err, "failed to get token default kubernetes service account token: failed to read token at path")

	_ = storage.Clear()
}

func TestNoServiceAccountTokenDir(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); time.Sleep(time.Second) }()

	storage, err := test.NewServiceAccountTokenStorage(t.TempDir())
	require.NoError(t, err)
	DefaultServiceAccountDir = storage.ServiceAccountTokenDir
	logger.Infof("service account token dir is %s", storage.ServiceAccountTokenDir)

	err = storage.Clear()
	require.NoError(t, err)

	_, err = GetServiceAccountToken(ctx)
	assert.ErrorContains(t, err, "failed to create token watcher: failed to add path")

	_ = storage.Clear()
}

func TestAudienceTokens(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); time.Sleep(time.Second) }()

	storage, err := test.NewAudienceTokensStorage(t.TempDir())
	require.NoError(t, err)
	DefaultAudienceTokensDir = storage.AudienceTokensDir
	logger.Infof("audience tokens dir is %s", storage.AudienceTokensDir)

	netcrackerTokenInitialValue := "netcracker_token_initial_value"
	err = storage.SaveTokenValue(AudienceNetcracker, netcrackerTokenInitialValue)
	require.NoError(t, err)

	dbaasTokenInitialValue := "dbaas_token_initial_value"
	err = storage.SaveTokenValue(AudienceDBaaS, dbaasTokenInitialValue)
	require.NoError(t, err)

	token, err := GetAudienceToken(ctx, AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, netcrackerTokenInitialValue, token)

	token, err = GetAudienceToken(ctx, AudienceDBaaS)
	require.NoError(t, err)
	assert.Equal(t, dbaasTokenInitialValue, token)

	netcrackerTokenSecondValue := "netcracker_token_second_value"
	err = storage.SaveTokenValue(AudienceNetcracker, netcrackerTokenSecondValue)
	require.NoError(t, err)

	token, err = GetAudienceToken(ctx, AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, netcrackerTokenSecondValue, token)

	dbaasTokenSecondValue := "dbaas_token_second_value"
	err = storage.SaveTokenValue(AudienceDBaaS, dbaasTokenSecondValue)
	require.NoError(t, err)

	token, err = GetAudienceToken(ctx, AudienceDBaaS)
	require.NoError(t, err)
	assert.Equal(t, dbaasTokenSecondValue, token)

	_ = storage.Clear()
}

func TestNoAudienceToken(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); time.Sleep(time.Second) }()

	storage, err := test.NewAudienceTokensStorage(t.TempDir())
	require.NoError(t, err)
	DefaultAudienceTokensDir = storage.AudienceTokensDir
	logger.Infof("audience tokens dir is %s", storage.AudienceTokensDir)

	_, err = GetAudienceToken(ctx, AudienceNetcracker)
	assert.ErrorContains(t, err, "token with audience netcracker was not found")

	err = storage.SaveTokenValue(AudienceNetcracker, "value")
	require.NoError(t, err)

	token, err := GetAudienceToken(ctx, AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, "value", token)

	err = storage.DeleteTokenFile(AudienceNetcracker)
	require.NoError(t, err)

	_, err = GetAudienceToken(ctx, AudienceNetcracker)
	assert.ErrorContains(t, err, "failed to get token by audience: netcracker: failed to read token at path")

	_ = storage.Clear()
}

func TestNoAudienceTokensDir(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); time.Sleep(time.Second) }()

	storage, err := test.NewAudienceTokensStorage(t.TempDir())
	require.NoError(t, err)
	DefaultAudienceTokensDir = storage.AudienceTokensDir
	logger.Infof("audience tokens dir is %s", storage.AudienceTokensDir)

	err = storage.Clear()
	require.NoError(t, err)

	_, err = GetAudienceToken(ctx, AudienceNetcracker)
	assert.ErrorContains(t, err, "failed to create token watcher: failed to refresh tokens cache: failed to get dir entries from tokenDir")

	_ = storage.Clear()
}

func TestEmptyAudience(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); time.Sleep(time.Second) }()

	_, err := GetAudienceToken(ctx, "")
	assert.ErrorContains(t, err, "audience is empty")
}
