package tokenverifier

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type errReadCloser struct {
	err error
}

func (e errReadCloser) Read(_ []byte) (int, error) {
	return 0, e.err
}

func (e errReadCloser) Close() error {
	return nil
}

func TestUnmarshalResponse_InvalidJSONWithJSONContentType(t *testing.T) {
	response := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	err := unmarshalResponse(response, []byte("{bad json"), &struct{}{})
	assert.ErrorContains(t, err, "got content-type = application/json, but could not unmarshal as json")
}

func TestCreateKeyFunction_HttpClientFailure(t *testing.T) {
	httpClient := &http.Client{
		Transport: roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
			return nil, errors.New("network down")
		}),
	}

	_, err := CreateKeyFunction(context.Background(), KeyFuncOptions{
		HttpClient:    httpClient,
		TrustedIssuer: "https://issuer.example.com",
	})
	assert.ErrorContains(t, err, "unexpected issue during oidc call to 'https://issuer.example.com/.well-known/openid-configuration'")
	assert.ErrorContains(t, err, "network down")
}

func TestCreateKeyFunction_ReadBodyFailure(t *testing.T) {
	httpClient := &http.Client{
		Transport: roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       errReadCloser{err: errors.New("read failed")},
				Header:     http.Header{},
			}, nil
		}),
	}

	_, err := CreateKeyFunction(context.Background(), KeyFuncOptions{
		HttpClient:    httpClient,
		TrustedIssuer: "https://issuer.example.com",
	})
	assert.ErrorContains(t, err, "unable to read oidc response body")
	assert.ErrorContains(t, err, "read failed")
}

func TestValidateIssuedAt_OnLeewayBoundary(t *testing.T) {
	token := &jwt.Token{Claims: jwt.MapClaims{
		"iat": float64(time.Now().Add(20 * time.Second).Unix()),
	}}
	err := ValidateIssuedAt(token)
	assert.NoError(t, err)

	token = &jwt.Token{Claims: jwt.MapClaims{
		"iat": float64(time.Now().Add(leeway).Unix()),
	}}
	err = ValidateIssuedAt(token)
	assert.NoError(t, err)
}

func TestSecureTransport_BaseRoundTripError(t *testing.T) {
	expectedErr := errors.New("base transport failed")
	transport := newSecureTransport(func() (string, error) {
		return "valid_token", nil
	}, "AKS")
	transport.base = roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		assert.Equal(t, "Bearer valid_token", request.Header.Get("Authorization"))
		return nil, expectedErr
	})

	request, err := http.NewRequest(http.MethodGet, "https://issuer.example.com", nil)
	assert.NoError(t, err)

	response, err := transport.RoundTrip(request)
	assert.Nil(t, response)
	assert.ErrorIs(t, err, expectedErr)
}

func TestCreateKeyFunction_UnmarshalResponseUsesBody(t *testing.T) {
	response := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"text/plain"},
		},
		Body: io.NopCloser(strings.NewReader("not json")),
	}
	body, err := io.ReadAll(response.Body)
	assert.NoError(t, err)

	err = unmarshalResponse(response, body, &struct{}{})
	assert.ErrorContains(t, err, "expected content-type = application/json")
}
