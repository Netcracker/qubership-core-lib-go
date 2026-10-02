package rest

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const tenantManagerUrl = "http://tenant-manager:8080/api/v4/tenants"

func stubToken(token string, err error) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		return token, err
	}
}

func newTestSender(mode security.M2MAuthMode, k8sErr error) *M2MRequestSender {
	sender := &M2MRequestSender{
		m2mAuthMode:             mode,
		k8sToken:                stubToken("k8s-token", k8sErr),
		legacyTargets:           newUrlCache(),
		internalGatewayHostname: "internal-gateway-service",
	}
	if mode.UsesLegacyToken() {
		sender.legacyToken = stubToken("legacy-token", nil)
	}
	return sender
}

type response struct {
	status int
	err    error
}

// receiver answers each call of its send function with the next response and records the tokens it got.
type receiver struct {
	responses []response
	tokens    []string
}

func respondInTurn(responses ...response) *receiver {
	return &receiver{responses: responses}
}

func (r *receiver) send(token string) (int, error) {
	next := r.responses[len(r.tokens)]
	r.tokens = append(r.tokens, token)
	return next.status, next.err
}

var (
	ok           = response{status: http.StatusOK}
	unauthorized = response{status: http.StatusUnauthorized}
)

func TestM2MRequestSender_Send(t *testing.T) {
	tests := []struct {
		name       string
		mode       security.M2MAuthMode
		responses  []response
		wantTokens []string
	}{
		{name: "legacy mode sends the legacy token", mode: security.M2MAuthModeLegacy, responses: []response{ok}, wantTokens: []string{"legacy-token"}},
		{name: "legacy mode returns a 401 without resending", mode: security.M2MAuthModeLegacy, responses: []response{unauthorized}, wantTokens: []string{"legacy-token"}},
		{name: "k8s mode sends the k8s token", mode: security.M2MAuthModeK8s, responses: []response{ok}, wantTokens: []string{"k8s-token"}},
		{name: "k8s mode returns a 401 without resending", mode: security.M2MAuthModeK8s, responses: []response{unauthorized}, wantTokens: []string{"k8s-token"}},
		{name: "hybrid mode sends the k8s token", mode: security.M2MAuthModeHybrid, responses: []response{ok}, wantTokens: []string{"k8s-token"}},
		{name: "hybrid mode resends with the legacy token after a 401", mode: security.M2MAuthModeHybrid, responses: []response{unauthorized, ok}, wantTokens: []string{"k8s-token", "legacy-token"}},
		{name: "hybrid mode does not resend after another status", mode: security.M2MAuthModeHybrid, responses: []response{{status: http.StatusForbidden}}, wantTokens: []string{"k8s-token"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := respondInTurn(tt.responses...)

			err := newTestSender(tt.mode, nil).Send(context.Background(), tenantManagerUrl, r.send)

			require.NoError(t, err)
			assert.Equal(t, tt.wantTokens, r.tokens)
		})
	}
}

func TestM2MRequestSender_Send_ReturnsErrorOfLastCall(t *testing.T) {
	handshakeErr := errors.New("websocket: bad handshake")
	r := respondInTurn(response{status: http.StatusUnauthorized, err: handshakeErr}, response{err: errors.New("connection refused")})

	err := newTestSender(security.M2MAuthModeHybrid, nil).Send(context.Background(), tenantManagerUrl, r.send)

	assert.EqualError(t, err, "connection refused")
	assert.Equal(t, []string{"k8s-token", "legacy-token"}, r.tokens, "a 401 that comes with an error is resent too")
}

func TestM2MRequestSender_Send_ReturnsSendErrorWithoutResending(t *testing.T) {
	sendErr := errors.New("connection refused")
	r := respondInTurn(response{err: sendErr})

	err := newTestSender(security.M2MAuthModeHybrid, nil).Send(context.Background(), tenantManagerUrl, r.send)

	assert.ErrorIs(t, err, sendErr)
	assert.Equal(t, []string{"k8s-token"}, r.tokens)
}

func TestM2MRequestSender_Send_K8sModeReturnsK8sTokenErrorWithoutSending(t *testing.T) {
	k8sErr := errors.New("token file is missing")
	r := respondInTurn()

	err := newTestSender(security.M2MAuthModeK8s, k8sErr).Send(context.Background(), tenantManagerUrl, r.send)

	assert.ErrorIs(t, err, k8sErr)
	assert.Empty(t, r.tokens)
}

func TestM2MRequestSender_Send_HybridModeSendsLegacyTokenWhenK8sTokenIsUnreadable(t *testing.T) {
	sender := newTestSender(security.M2MAuthModeHybrid, errors.New("token file is missing"))
	r := respondInTurn(ok)

	err := sender.Send(context.Background(), tenantManagerUrl, r.send)

	require.NoError(t, err)
	assert.Equal(t, []string{"legacy-token"}, r.tokens)
}

func TestM2MRequestSender_Send_HybridModeKeepsLegacyTokenForTargetAfterUnreadableK8sToken(t *testing.T) {
	sender := newTestSender(security.M2MAuthModeHybrid, errors.New("token file is missing"))
	r := respondInTurn(ok, ok)

	require.NoError(t, sender.Send(context.Background(), tenantManagerUrl, r.send))
	sender.k8sToken = stubToken("k8s-token", nil)
	require.NoError(t, sender.Send(context.Background(), tenantManagerUrl, r.send))

	assert.Equal(t, []string{"legacy-token", "legacy-token"}, r.tokens)
}

func TestM2MRequestSender_Send_HybridModeReturnsLegacyTokenErrorAfter401(t *testing.T) {
	legacyErr := errors.New("keycloak is down")
	sender := newTestSender(security.M2MAuthModeHybrid, nil)
	sender.legacyToken = stubToken("", legacyErr)
	r := respondInTurn(unauthorized)

	err := sender.Send(context.Background(), tenantManagerUrl, r.send)

	assert.ErrorIs(t, err, legacyErr)
	assert.Equal(t, []string{"k8s-token"}, r.tokens)
}

func TestM2MRequestSender_Send_HybridModeKeepsLegacyTokenForTargetAfterSuccessfulResend(t *testing.T) {
	sender := newTestSender(security.M2MAuthModeHybrid, nil)
	r := respondInTurn(unauthorized, ok, ok, ok)

	require.NoError(t, sender.Send(context.Background(), tenantManagerUrl, r.send))
	require.NoError(t, sender.Send(context.Background(), tenantManagerUrl+"/1", r.send))
	require.NoError(t, sender.Send(context.Background(), "http://paas-mediation:8080/api/v2/routes", r.send))

	assert.Equal(t, []string{"k8s-token", "legacy-token", "legacy-token", "k8s-token"}, r.tokens)
}

func TestM2MRequestSender_Send_HybridModeDoesNotKeepLegacyTokenAfterFailedResend(t *testing.T) {
	sender := newTestSender(security.M2MAuthModeHybrid, nil)
	r := respondInTurn(unauthorized, unauthorized, ok)

	require.NoError(t, sender.Send(context.Background(), tenantManagerUrl, r.send))
	require.NoError(t, sender.Send(context.Background(), tenantManagerUrl, r.send))

	assert.Equal(t, []string{"k8s-token", "legacy-token", "k8s-token"}, r.tokens)
}

func TestM2MRequestSender_Send_HybridModeKeysInternalGatewayTargetsByService(t *testing.T) {
	sender := newTestSender(security.M2MAuthModeHybrid, nil)
	r := respondInTurn(unauthorized, ok, ok, ok)

	require.NoError(t, sender.Send(context.Background(), "http://internal-gateway-service:8080/api/v1/tenant-manager/tenants", r.send))
	require.NoError(t, sender.Send(context.Background(), "http://internal-gateway-service:8080/api/v1/tenant-manager/routes", r.send))
	require.NoError(t, sender.Send(context.Background(), "http://internal-gateway-service:8080/api/v1/site-management/routes", r.send))

	assert.Equal(t, []string{"k8s-token", "legacy-token", "legacy-token", "k8s-token"}, r.tokens)
}

func TestM2MRequestSender_Send_HybridModeKeysWatchApiTargetsByPrefix(t *testing.T) {
	sender := newTestSender(security.M2MAuthModeHybrid, nil)
	r := respondInTurn(unauthorized, ok, ok)

	require.NoError(t, sender.Send(context.Background(), "ws://internal-gateway-service:8080/watchapi/v2/paas-mediation/namespaces/ns/routes", r.send))
	require.NoError(t, sender.Send(context.Background(), "ws://internal-gateway-service:8080/watchapi/v2/paas-mediation/namespaces/ns/services", r.send))

	assert.Equal(t, []string{"k8s-token", "legacy-token", "legacy-token"}, r.tokens)
}

func TestM2MRequestSender_Send_HybridModeRejectsUnparsableUrl(t *testing.T) {
	r := respondInTurn()

	err := newTestSender(security.M2MAuthModeHybrid, nil).Send(context.Background(), "://invalid-url", r.send)

	assert.ErrorContains(t, err, "url can not be parsed")
	assert.Empty(t, r.tokens)
}

func TestNewM2MRequestSender_HybridModeSendsRegisteredTokens(t *testing.T) {
	registerStubTokens()
	t.Setenv(security.M2MAuthModeEnv, "hybrid")
	r := respondInTurn(unauthorized, ok)

	err := NewM2MRequestSender().Send(context.Background(), tenantManagerUrl, r.send)

	require.NoError(t, err)
	assert.Equal(t, []string{"k8s-token", "legacy-token"}, r.tokens)
}

func TestNewM2MRequestSender_UnsupportedModePanics(t *testing.T) {
	t.Setenv(security.M2MAuthModeEnv, "false")

	assert.Panics(t, func() { NewM2MRequestSender() })
}

func TestNewM2MRequestSender_K8sModeDoesNotLoadTokenProvider(t *testing.T) {
	t.Setenv(security.M2MAuthModeEnv, "k8s")

	assert.Nil(t, NewM2MRequestSender().legacyToken)
}
