package tokensource

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectableTokenSourceUsesFileProviderWhenLocalDevDisabled(t *testing.T) {
	t.Setenv("PROFILE", "")
	source := newSelectableTokenSource()
	require.NotNil(t, source.delegate)
	_, isFile := source.delegate.(*DefaultTokenFileProvider)
	assert.True(t, isFile)
}

func TestSelectableTokenSourceUsesLocalDevWhenEnabled(t *testing.T) {
	t.Setenv("PROFILE", "dev")
	source := newSelectableTokenSource()
	_, isLocalDev := source.delegate.(*localDevTokenSource)
	assert.True(t, isLocalDev)

	_, err := source.GetAudienceToken(context.Background(), "")
	assert.ErrorContains(t, err, "audience is empty")
}
