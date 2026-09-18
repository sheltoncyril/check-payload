package validations

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openshift/check-payload/internal/types"
)

// denylist mirrors rust_denied_crypto in config.toml. The test sets it directly
// so it exercises the shipped list without loading the config package.
var rustFixtureDenylist = []string{
	"ring", "aws-lc-rs", "aws-lc-sys", "aws-lc-fips-sys",
	"boring", "boring-sys", "openssl-src",
	"sha1", "sha2", "sha3", "md-5", "hmac", "aes", "aes-gcm",
	"chacha20poly1305", "ctr", "cbc", "rsa", "ecdsa",
	"ed25519-dalek", "curve25519-dalek", "x25519-dalek", "p256", "p384",
}

// TestScanRealRustBinary runs the full rust validation arm against committed
// Rust binaries, catching regressions the synthetic unit tests cannot: real
// .symtab/.dynsym symbol reads, real .dep-v0 section parsing, and the
// stripped-binary degradation. Fixtures are built by build_rust_fixtures.sh.
func TestScanRealRustBinary(t *testing.T) {
	const topDir = "../../test/resources/rust"
	if _, err := os.Stat(topDir); err != nil {
		t.Skip("rust fixtures not built; run: test/resources/build_rust_fixtures.sh")
	}

	origDenied, origCertified := rustDeniedCrypto, rustCertifiedModules
	t.Cleanup(func() { rustDeniedCrypto, rustCertifiedModules = origDenied, origCertified })
	SetRustDeniedCrypto(rustFixtureDenylist)
	// No Rust module is attested, so every detected provider must fail.
	SetRustCertifiedModules(nil)

	tests := []struct {
		name            string
		wantSuccess     bool
		wantLevel       types.ErrorLevel
		wantIs          error
		wantContains    []string
		wantNotContains []string
		note            string
	}{
		{
			name:         "ring-bin",
			wantLevel:    types.Error,
			wantIs:       types.ErrRustBundledCrypto,
			wantContains: []string{"ring"},
			note:         "bundled backend detected, not an attested module",
		},
		{
			name:         "rustcrypto",
			wantLevel:    types.Error,
			wantIs:       types.ErrRustBundledCrypto,
			wantContains: []string{"sha2"},
			note:         "pure-Rust primitive detected from the manifest, not an attested module",
		},
		{
			name:      "ring-corrupt",
			wantLevel: types.Error,
			wantIs:    types.ErrRustInvalidAuditable,
			note:      "present-but-unparseable manifest fails closed",
		},
		{
			name:        "clean",
			wantSuccess: true,
			note:        "no crypto, manifest present",
		},
		{
			name:      "clean-noaudit",
			wantLevel: types.Warning,
			wantIs:    types.ErrRustNoAuditable,
			note:      "no crypto, no manifest: inconclusive warning",
		},
		{
			name:      "ring-stripped",
			wantLevel: types.Warning,
			wantIs:    types.ErrRustNoAuditable,
			// A stripped binary with bundled crypto but no manifest yields no module
			// candidate, so it warns rather than fails. This is the detection limit.
			// Real assurance needs a cargo-auditable build that survives stripping.
			note: "stripped bundled-crypto binary with no manifest is only a warning",
		},
	}

	ctx := context.Background()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := ScanBinary(ctx, topDir, "/"+tc.name, nil)
			require.False(t, res.Skip, "binary was skipped, expected it to be scanned")

			if tc.wantSuccess {
				require.Nil(t, res.Error, "expected success, got %v", res.Error)
				return
			}

			require.NotNil(t, res.Error, "expected a validation result")
			require.Equal(t, tc.wantLevel, res.Error.Level)
			require.ErrorIs(t, res.Error.Error, tc.wantIs)
			for _, sub := range tc.wantContains {
				require.ErrorContains(t, res.Error.Error, sub)
			}
			for _, sub := range tc.wantNotContains {
				require.NotContains(t, res.Error.Error.Error(), sub)
			}
		})
	}
}
