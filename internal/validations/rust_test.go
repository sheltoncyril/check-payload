package validations

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openshift/check-payload/internal/rust"
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

// certSet builds a certified-modules map that attests each name on name alone.
func certSet(modules ...string) map[string][]certifiedModule {
	m := make(map[string][]certifiedModule, len(modules))
	for _, mod := range modules {
		m[mod] = []certifiedModule{{}}
	}
	return m
}

func TestClassifyRustCandidates(t *testing.T) {
	tests := []struct {
		name           string
		candidates     []rust.Candidate
		certified      map[string][]certifiedModule
		wantAttested   []string
		wantUnattested []string
	}{
		{
			name:           "detected provider without attestation is unattested and labeled with version",
			candidates:     []rust.Candidate{{Name: "ring", Version: "0.17.14", Source: rust.SourceManifest}},
			certified:      certSet("openssl", "go"),
			wantUnattested: []string{"ring 0.17.14"},
		},
		{
			name:         "detected provider attested on name alone",
			candidates:   []rust.Candidate{{Name: "aws-lc-fips-sys", Version: "0.13.3", Source: rust.SourceManifest}},
			certified:    certSet("aws-lc-fips-sys"),
			wantAttested: []string{"aws-lc-fips-sys"},
		},
		{
			name:       "attested name but version below configured minimum fails",
			candidates: []rust.Candidate{{Name: "aws-lc-fips-sys", Version: "0.12.0", Source: rust.SourceManifest}},
			certified: map[string][]certifiedModule{
				"aws-lc-fips-sys": {{minVersion: "0.13.0"}},
			},
			wantUnattested: []string{"aws-lc-fips-sys 0.12.0"},
		},
		{
			name:       "attested name with version in configured range passes",
			candidates: []rust.Candidate{{Name: "aws-lc-fips-sys", Version: "0.13.3", Source: rust.SourceManifest}},
			certified: map[string][]certifiedModule{
				"aws-lc-fips-sys": {{minVersion: "0.13.0", maxVersion: "0.13.9"}},
			},
			wantAttested: []string{"aws-lc-fips-sys"},
		},
		{
			name:       "configured range but symbol-only candidate has no version to verify",
			candidates: []rust.Candidate{{Name: "aws-lc", Source: rust.SourceSymbol}},
			certified: map[string][]certifiedModule{
				"aws-lc": {{minVersion: "0.13.0"}},
			},
			wantUnattested: []string{"aws-lc"},
		},
		{
			name: "mixed attested and unattested keeps only the unattested in failures",
			candidates: []rust.Candidate{
				{Name: "aws-lc-fips-sys", Version: "0.13.3", Source: rust.SourceManifest},
				{Name: "sha2", Version: "0.10.8", Source: rust.SourceManifest},
			},
			certified:      certSet("aws-lc-fips-sys"),
			wantAttested:   []string{"aws-lc-fips-sys"},
			wantUnattested: []string{"sha2 0.10.8"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attested, unattested := classifyRustCandidates(tt.candidates, tt.certified)
			require.Equal(t, tt.wantAttested, attested)
			require.Equal(t, tt.wantUnattested, unattested)
		})
	}
}

// TestValidateRustCryptoVerdict exercises the attestation-first verdict: static
// linkage, system-openssl positive evidence, and the indeterminate outcomes.
func TestValidateRustCryptoVerdict(t *testing.T) {
	origDenied, origCertified := rustDeniedCrypto, rustCertifiedModules
	t.Cleanup(func() { rustDeniedCrypto, rustCertifiedModules = origDenied, origCertified })
	SetRustDeniedCrypto([]string{"ring", "aws-lc-fips-sys", "sha2"})
	SetRustCertifiedModules([]types.FipsModule{{Module: "aws-lc-fips-sys"}})

	fipsManifest := &rust.Sbom{Packages: []rust.Package{{Name: "aws-lc-fips-sys", Version: "0.13.3", Kind: "runtime"}}}
	ringManifest := &rust.Sbom{Packages: []rust.Package{{Name: "ring", Version: "0.17.14", Kind: "runtime"}}}
	cleanManifest := &rust.Sbom{Packages: []rust.Package{{Name: "serde", Version: "1.0.0", Kind: "runtime"}}}

	tests := []struct {
		name      string
		baton     *Baton
		wantNil   bool
		wantLevel types.ErrorLevel
		wantIs    error
		wantMod   string
	}{
		{
			name:    "static binary with an attested bundled provider passes",
			baton:   &Baton{Static: true, RustAudit: fipsManifest},
			wantNil: true,
			wantMod: "aws-lc-fips-sys",
		},
		{
			name:      "static binary with an unattested provider fails on the crypto, not the static rule",
			baton:     &Baton{Static: true, RustAudit: ringManifest},
			wantLevel: types.Error,
			wantIs:    types.ErrRustBundledCrypto,
		},
		{
			name:      "static binary with no provider falls back to the static rule",
			baton:     &Baton{Static: true, RustAudit: cleanManifest},
			wantLevel: types.Error,
			wantIs:    types.ErrNotDynLinked,
		},
		{
			name:    "dynamic binary linking system openssl is compliant",
			baton:   &Baton{RustAudit: cleanManifest, ModulesUsed: []string{moduleOpenssl}},
			wantNil: true,
		},
		{
			name:      "dynamic clean binary with a manifest is indeterminate, not a pass",
			baton:     &Baton{RustAudit: cleanManifest},
			wantLevel: types.Warning,
			wantIs:    types.ErrRustNoProvider,
		},
		{
			name:      "dynamic binary with no manifest warns as inconclusive",
			baton:     &Baton{},
			wantLevel: types.Warning,
			wantIs:    types.ErrRustNoAuditable,
		},
		{
			name:      "corrupt manifest fails closed",
			baton:     &Baton{RustAuditErr: errors.New("zlib: invalid header")},
			wantLevel: types.Error,
			wantIs:    types.ErrRustInvalidAuditable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateRustCrypto(context.Background(), "", tt.baton)
			if tt.wantNil {
				require.Nil(t, got)
				if tt.wantMod != "" {
					require.Contains(t, tt.baton.ModulesUsed, tt.wantMod)
				}
				return
			}
			require.NotNil(t, got)
			require.Equal(t, tt.wantLevel, got.Level)
			require.ErrorIs(t, got.Error, tt.wantIs)
		})
	}
}
