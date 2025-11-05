package tokensource

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	serviceAccountTokensStorage *test.ServiceAccountTokenStorage
	audienceTokensStorage       *test.AudienceTokensStorage
)

func beforeEach(t *testing.T) {
	var err error

	serviceAccountTokensStorage, err = test.NewServiceAccountTokenStorage(t.TempDir())
	require.NoError(t, err)
	DefaultServiceAccountDir = serviceAccountTokensStorage.ServiceAccountTokenDir
	logger.Infof("service account token dir is %s", serviceAccountTokensStorage.ServiceAccountTokenDir)

	audienceTokensStorage, err = test.NewAudienceTokensStorage(t.TempDir())
	require.NoError(t, err)
	DefaultAudienceTokensDir = audienceTokensStorage.AudienceTokensDir
	logger.Infof("audience tokens dir is %s", audienceTokensStorage.AudienceTokensDir)
}
func afterEach(_ *testing.T) {
	_ = serviceAccountTokensStorage.Clear()
	_ = audienceTokensStorage.Clear()
}
func TestMain(m *testing.M) {
	exitCode := m.Run()
	os.Exit(exitCode)
}
func TestServiceAccountToken(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountTokenInitialValue := "service_account_token_initial_value"
	err := serviceAccountTokensStorage.SaveTokenValue(serviceAccountTokenInitialValue)
	require.NoError(t, err)

	token, err := GetServiceAccountToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, serviceAccountTokenInitialValue, token)

	serviceAccountTokenSecondValue := "service_account_token_second_value"
	err = serviceAccountTokensStorage.SaveTokenValue(serviceAccountTokenSecondValue)
	require.NoError(t, err)

	token, err = GetServiceAccountToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, serviceAccountTokenSecondValue, token)
}
func TestNoServiceAccountToken(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	err := serviceAccountTokensStorage.DeleteTokenFile()
	require.NoError(t, err)

	_, err = GetServiceAccountToken(ctx)
	assert.ErrorContains(t, err, "failed to get token default kubernetes service account token: failed to read token at path")

	err = serviceAccountTokensStorage.SaveTokenValue("value")
	require.NoError(t, err)

	token, err := GetServiceAccountToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, "value", token)

	err = serviceAccountTokensStorage.DeleteTokenFile()
	require.NoError(t, err)

	_, err = GetServiceAccountToken(ctx)
	assert.ErrorContains(t, err, "failed to get token default kubernetes service account token: failed to read token at path")
}
func TestNoServiceAccountTokenDir(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	err := serviceAccountTokensStorage.Clear()
	require.NoError(t, err)

	_, err = GetServiceAccountToken(ctx)
	assert.ErrorContains(t, err, "failed to create token watcher: failed to add path")
}
func TestAudienceTokens(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	netcrackerTokenInitialValue := "netcracker_token_initial_value"
	err := audienceTokensStorage.SaveTokenValue(AudienceNetcracker, netcrackerTokenInitialValue)
	require.NoError(t, err)

	dbaasTokenInitialValue := "dbaas_token_initial_value"
	err = audienceTokensStorage.SaveTokenValue(AudienceDBaaS, dbaasTokenInitialValue)
	require.NoError(t, err)

	token, err := GetAudienceToken(ctx, AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, netcrackerTokenInitialValue, token)

	token, err = GetAudienceToken(ctx, AudienceDBaaS)
	require.NoError(t, err)
	assert.Equal(t, dbaasTokenInitialValue, token)

	netcrackerTokenSecondValue := "netcracker_token_second_value"
	err = audienceTokensStorage.SaveTokenValue(AudienceNetcracker, netcrackerTokenSecondValue)
	require.NoError(t, err)

	token, err = GetAudienceToken(ctx, AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, netcrackerTokenSecondValue, token)

	dbaasTokenSecondValue := "dbaas_token_second_value"
	err = audienceTokensStorage.SaveTokenValue(AudienceDBaaS, dbaasTokenSecondValue)
	require.NoError(t, err)

	token, err = GetAudienceToken(ctx, AudienceDBaaS)
	require.NoError(t, err)
	assert.Equal(t, dbaasTokenSecondValue, token)
}
func TestNoAudienceToken(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	_, err := GetAudienceToken(ctx, AudienceNetcracker)
	assert.ErrorContains(t, err, "token with audience netcracker was not found")

	err = audienceTokensStorage.SaveTokenValue(AudienceNetcracker, "value")
	require.NoError(t, err)

	token, err := GetAudienceToken(ctx, AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, "value", token)

	err = audienceTokensStorage.DeleteTokenFile(AudienceNetcracker)
	require.NoError(t, err)

	_, err = GetAudienceToken(ctx, AudienceNetcracker)
	assert.ErrorContains(t, err, "failed to get token by audience: netcracker: failed to read token at path")
}
func TestNoAudienceTokensDir(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	err := audienceTokensStorage.Clear()
	require.NoError(t, err)

	_, err = GetAudienceToken(ctx, AudienceNetcracker)
	assert.ErrorContains(t, err, "failed to create token watcher: failed to refresh tokens cache: failed to get dir entries from tokenDir")

}
func TestEmptyAudience(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	_, err := GetAudienceToken(ctx, "")
	assert.ErrorContains(t, err, "audience is empty")
}
