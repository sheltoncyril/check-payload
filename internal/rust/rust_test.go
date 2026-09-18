package rust

import (
	"bytes"
	"compress/zlib"
	"debug/elf"
	"encoding/json"
	"io"
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
			name: "non-native build dependency is ignored",
			sbom: &Sbom{Packages: []Package{{Name: "ring", Kind: "build"}}},
			want: nil,
		},
		{
			name: "development dependency is ignored",
			sbom: &Sbom{Packages: []Package{{Name: "ring", Kind: "development"}}},
			want: nil,
		},
		{
			name: "native-source build dependency is still caught",
			sbom: &Sbom{Packages: []Package{{Name: "openssl-src", Kind: "build"}}},
			want: []string{"openssl-src"},
		},
		{
			name: "allowed crate is not flagged",
			sbom: &Sbom{Packages: []Package{{Name: "serde", Kind: "runtime"}}},
			want: nil,
		},
		{
			name: "mixed set reports runtime denied crates and native-source build deps",
			sbom: &Sbom{Packages: []Package{
				{Name: "serde", Kind: "runtime"},
				{Name: "ring", Kind: "runtime"},
				{Name: "openssl-src", Kind: "build"},
			}},
			want: []string{"ring", "openssl-src"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.sbom.LinkedCrypto(denied))
		})
	}
}

func TestCryptoModuleCandidates(t *testing.T) {
	denied := map[string]struct{}{
		"ring": {}, "sha2": {}, "openssl-src": {}, "aws-lc-fips-sys": {}, "aws-lc-sys": {},
	}

	tests := []struct {
		name    string
		sbom    *Sbom
		symbols []string
		want    []string
	}{
		{
			name:    "no manifest falls back to symbol backends",
			symbols: []string{"ring", "bundled-openssl"},
			want:    []string{"bundled-openssl", "ring"},
		},
		{
			name:    "manifest crate and its symbol backend dedup to one name",
			sbom:    &Sbom{Packages: []Package{{Name: "ring", Kind: "runtime"}}},
			symbols: []string{"ring"},
			want:    []string{"ring"},
		},
		{
			name:    "precise fips crate suppresses the coarse aws-lc symbol",
			sbom:    &Sbom{Packages: []Package{{Name: "aws-lc-fips-sys", Kind: "build"}}},
			symbols: []string{"aws-lc"},
			want:    []string{"aws-lc-fips-sys"},
		},
		{
			name:    "symbol backend with no manifest crate of its family is kept",
			sbom:    &Sbom{Packages: []Package{{Name: "serde", Kind: "runtime"}}},
			symbols: []string{"aws-lc"},
			want:    []string{"aws-lc"},
		},
		{
			name: "pure-Rust primitive from the manifest with no symbol",
			sbom: &Sbom{Packages: []Package{{Name: "sha2", Kind: "runtime"}}},
			want: []string{"sha2"},
		},
		{
			name: "clean binary yields no candidate",
			sbom: &Sbom{Packages: []Package{{Name: "serde", Kind: "runtime"}}},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, CryptoModuleCandidates(tt.sbom, denied, tt.symbols))
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

func TestParseAuditableRejectsZipBomb(t *testing.T) {
	// A small compressed section that inflates past the decompression cap must
	// fail rather than be read unbounded into memory.
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, err := io.CopyN(zw, zeroReader{}, maxDecompressed+1)
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	// Assert on the cap specifically: NUL bytes would make json.Unmarshal error
	// on their own, so a bare require.Error would pass even without the guard.
	_, err = ParseAuditable(buf.Bytes())
	require.ErrorContains(t, err, "exceeds")
}

// zeroReader is an infinite source of NUL bytes, which compress to almost nothing.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
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
