package validations

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openshift/check-payload/internal/types"
)

func TestValidateRustCryptoFailsClosedOnCorruptManifest(t *testing.T) {
	// A present-but-unparseable manifest must fail as an error, not fall through
	// to the absent-manifest warning.
	baton := &Baton{RustAuditErr: errors.New("zlib: invalid header")}
	got := validateRustCrypto(context.Background(), "", baton)
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

func TestSetRustCertifiedModules(t *testing.T) {
	orig := rustCertifiedModules
	t.Cleanup(func() { rustCertifiedModules = orig })

	SetRustCertifiedModules([]types.FipsModule{{Module: "aws-lc-fips-sys"}, {Module: "openssl"}})
	require.Contains(t, rustCertifiedModules, "aws-lc-fips-sys")
	require.Contains(t, rustCertifiedModules, "openssl")

	SetRustCertifiedModules(nil)
	require.Empty(t, rustCertifiedModules)
}

func certSet(modules ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(modules))
	for _, mod := range modules {
		m[mod] = struct{}{}
	}
	return m
}

func TestClassifyRustCrypto(t *testing.T) {
	tests := []struct {
		name         string
		candidates   []string
		hasManifest  bool
		certified    map[string]struct{}
		wantAttested []string
		wantNil      bool
		wantLevel    types.ErrorLevel
		wantIs       error
		wantMsgHas   []string
	}{
		{
			name:       "detected provider without attestation fails and names it",
			candidates: []string{"ring"},
			certified:  certSet("openssl", "go"),
			wantLevel:  types.Error,
			wantIs:     types.ErrRustBundledCrypto,
			wantMsgHas: []string{"ring"},
		},
		{
			name:         "detected provider with attestation passes and is recorded",
			candidates:   []string{"aws-lc-fips-sys"},
			hasManifest:  true,
			certified:    certSet("aws-lc-fips-sys"),
			wantNil:      true,
			wantAttested: []string{"aws-lc-fips-sys"},
		},
		{
			name:         "mixed attested and unattested fails naming only the unattested",
			candidates:   []string{"aws-lc-fips-sys", "sha2"},
			hasManifest:  true,
			certified:    certSet("aws-lc-fips-sys"),
			wantLevel:    types.Error,
			wantIs:       types.ErrRustBundledCrypto,
			wantMsgHas:   []string{"sha2"},
			wantAttested: []string{"aws-lc-fips-sys"},
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
			attested, got := classifyRustCrypto(tt.candidates, tt.hasManifest, tt.certified)
			require.Equal(t, tt.wantAttested, attested)
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
