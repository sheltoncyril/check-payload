package validations

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openshift/check-payload/internal/types"
)

func TestValidateRustBundledCryptoFailsClosedOnCorruptManifest(t *testing.T) {
	// A present-but-unparseable manifest must fail as an error, not fall through
	// to the absent-manifest warning.
	baton := &Baton{RustAuditErr: errors.New("zlib: invalid header")}
	got := validateRustBundledCrypto(context.Background(), "", baton)
	require.NotNil(t, got)
	require.Equal(t, types.Error, got.Level)
	require.ErrorIs(t, got.Error, types.ErrRustInvalidAuditable)
}

func TestSetRustDeniedCrypto(t *testing.T) {
	orig := rustDeniedCrypto
	t.Cleanup(func() { rustDeniedCrypto = orig })

	// The list is set from config wholesale, with no in-code fallback.
	SetRustDeniedCrypto([]string{"foo", "bar"})
	require.Contains(t, rustDeniedCrypto, "foo")
	require.Contains(t, rustDeniedCrypto, "bar")

	// An empty config list leaves an empty denylist (the symbol scan still runs).
	SetRustDeniedCrypto(nil)
	require.Empty(t, rustDeniedCrypto)
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
