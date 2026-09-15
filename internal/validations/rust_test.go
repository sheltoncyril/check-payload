package validations

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openshift/check-payload/internal/types"
)

func TestSetRustDeniedCrypto(t *testing.T) {
	orig := rustDeniedCrypto
	t.Cleanup(func() { rustDeniedCrypto = orig })

	// A non-empty list replaces the active denylist wholesale.
	SetRustDeniedCrypto([]string{"foo", "bar"})
	require.Contains(t, rustDeniedCrypto, "foo")
	require.Contains(t, rustDeniedCrypto, "bar")
	require.NotContains(t, rustDeniedCrypto, "ring")
	// The built-in default is never mutated in place.
	require.Contains(t, defaultDeniedRustCrypto, "ring")

	// An empty list is a no-op: it does not clear a prior replace.
	SetRustDeniedCrypto(nil)
	require.Contains(t, rustDeniedCrypto, "foo")
	require.NotContains(t, rustDeniedCrypto, "ring")
}

func TestClassifyRustCrypto(t *testing.T) {
	tests := []struct {
		name        string
		symbols     []string
		crates      []string
		hasManifest bool
		wantNil     bool
		wantLevel   types.ErrorLevel
		wantIs      error
		wantMsgHas  []string
	}{
		{
			name:       "bundled backend in symbols fails",
			symbols:    []string{"ring"},
			wantLevel:  types.Error,
			wantIs:     types.ErrRustBundledCrypto,
			wantMsgHas: []string{"symbols: ring"},
		},
		{
			name:        "denied crate in manifest fails",
			crates:      []string{"sha2"},
			hasManifest: true,
			wantLevel:   types.Error,
			wantIs:      types.ErrRustBundledCrypto,
			wantMsgHas:  []string{"manifest: sha2"},
		},
		{
			name:        "both signals fail and both are reported",
			symbols:     []string{"ring"},
			crates:      []string{"sha2"},
			hasManifest: true,
			wantLevel:   types.Error,
			wantIs:      types.ErrRustBundledCrypto,
			wantMsgHas:  []string{"symbols: ring", "manifest: sha2"},
		},
		{
			name:        "clean with manifest passes",
			hasManifest: true,
			wantNil:     true,
		},
		{
			name:      "clean without manifest warns",
			wantLevel: types.Warning,
			wantIs:    types.ErrRustNoAuditable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyRustCrypto(tt.symbols, tt.crates, tt.hasManifest)
			if tt.wantNil {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, tt.wantLevel, got.Level)
			require.ErrorIs(t, got.Error, tt.wantIs)
			for _, sub := range tt.wantMsgHas {
				require.Contains(t, got.Error.Error(), sub)
			}
		})
	}
}
