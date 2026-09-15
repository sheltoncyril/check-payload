package rust

import (
	"bytes"
	"compress/zlib"
	"debug/elf"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCryptoBackendForSymbol(t *testing.T) {
	tests := []struct {
		name        string
		symbol      string
		wantBackend string
		wantOK      bool
	}{
		{"modern ring", "ring_core_0_17_14__x25519_public_from_private", "ring", true},
		{"ring openssl-derived symbol attributes to ring", "ring_core_0_17_14__OPENSSL_cpuid_setup", "ring", true},
		{"legacy ring", "GFp_x25519_public_from_private", "ring", true},
		{"vendored openssl", "OPENSSL_init_crypto", "bundled-openssl", true},
		{"boringssl", "BORINGSSL_self_test", "boringssl", true},
		{"aws-lc version prefixed", "aws_lc_0_25_0_EVP_DigestInit", "aws-lc", true},
		{"aws-lc macro prefix", "AWSLC_fips_evp_pkey_methods", "aws-lc", true},
		{"system openssl import is not a backend prefix", "EVP_DigestInit", "", false},
		{"sha256 helper is not matched (no OPENSSL_ prefix)", "SHA256_Init", "", false},
		{"ordinary symbol", "main", "", false},
		{"empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, ok := cryptoBackendForSymbol(tt.symbol)
			require.Equal(t, tt.wantOK, ok)
			require.Equal(t, tt.wantBackend, backend)
		})
	}
}

func TestDefinedCryptoBackends(t *testing.T) {
	const defined = elf.SectionIndex(1) // any non-UNDEF section

	tests := []struct {
		name string
		syms []elf.Symbol
		want []string
	}{
		{
			name: "defined ring symbol is found",
			syms: []elf.Symbol{{Name: "ring_core_0_17_14__sha256", Section: defined}},
			want: []string{"ring"},
		},
		{
			name: "undefined import of the same name is ignored",
			syms: []elf.Symbol{{Name: "ring_core_0_17_14__sha256", Section: elf.SHN_UNDEF}},
			want: nil,
		},
		{
			name: "undefined system openssl import is not flagged",
			syms: []elf.Symbol{{Name: "OPENSSL_init_crypto", Section: elf.SHN_UNDEF}},
			want: nil,
		},
		{
			name: "defined vendored openssl is flagged",
			syms: []elf.Symbol{{Name: "OPENSSL_init_crypto", Section: defined}},
			want: []string{"bundled-openssl"},
		},
		{
			name: "every matching symbol is reported (BundledCryptoBackends dedups)",
			syms: []elf.Symbol{
				{Name: "ring_core_0_17_14__a", Section: defined},
				{Name: "ring_core_0_17_14__b", Section: defined},
				{Name: "GFp_c", Section: defined},
			},
			want: []string{"ring", "ring", "ring"},
		},
		{
			name: "ordinary symbols yield nothing",
			syms: []elf.Symbol{{Name: "main", Section: defined}, {Name: "_start", Section: defined}},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, definedCryptoBackends(tt.syms))
		})
	}
}

func TestLinkedCrypto(t *testing.T) {
	denied := map[string]struct{}{"ring": {}, "sha2": {}, "openssl-src": {}}

	tests := []struct {
		name string
		sbom *Sbom
		want []string
	}{
		{"nil sbom", nil, nil},
		{
			name: "runtime denied crate is found",
			sbom: &Sbom{Packages: []Package{{Name: "ring", Kind: "runtime"}}},
			want: []string{"ring"},
		},
		{
			name: "empty kind is treated as runtime",
			sbom: &Sbom{Packages: []Package{{Name: "sha2", Kind: ""}}},
			want: []string{"sha2"},
		},
		{
			name: "build dependency is ignored",
			sbom: &Sbom{Packages: []Package{{Name: "openssl-src", Kind: "build"}}},
			want: nil,
		},
		{
			name: "development dependency is ignored",
			sbom: &Sbom{Packages: []Package{{Name: "ring", Kind: "development"}}},
			want: nil,
		},
		{
			name: "allowed crate is not flagged",
			sbom: &Sbom{Packages: []Package{{Name: "serde", Kind: "runtime"}}},
			want: nil,
		},
		{
			name: "mixed set reports only the runtime denied crates",
			sbom: &Sbom{Packages: []Package{
				{Name: "serde", Kind: "runtime"},
				{Name: "ring", Kind: "runtime"},
				{Name: "openssl-src", Kind: "build"},
			}},
			want: []string{"ring"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.sbom.LinkedCrypto(denied))
		})
	}
}

func TestParseAuditable(t *testing.T) {
	want := &Sbom{Packages: []Package{
		{Name: "ring", Version: "0.17.14", Kind: "runtime"},
		{Name: "serde", Version: "1.0.0", Kind: ""},
	}}
	got, err := ParseAuditable(zlibJSON(t, want))
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestParseAuditableRejectsNonZlib(t *testing.T) {
	_, err := ParseAuditable([]byte("not zlib"))
	require.Error(t, err)
}

func zlibJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, err = zw.Write(raw)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}
