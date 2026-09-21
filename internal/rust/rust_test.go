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
		want []Candidate
	}{
		{"nil sbom", nil, nil},
		{
			name: "runtime denied crate is found with its version",
			sbom: &Sbom{Packages: []Package{{Name: "ring", Version: "0.17.14", Kind: "runtime"}}},
			want: []Candidate{{Name: "ring", Version: "0.17.14", Source: SourceManifest}},
		},
		{
			name: "empty kind is treated as runtime",
			sbom: &Sbom{Packages: []Package{{Name: "sha2", Version: "0.10.8", Kind: ""}}},
			want: []Candidate{{Name: "sha2", Version: "0.10.8", Source: SourceManifest}},
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
			sbom: &Sbom{Packages: []Package{{Name: "openssl-src", Version: "300.5.0", Kind: "build"}}},
			want: []Candidate{{Name: "openssl-src", Version: "300.5.0", Source: SourceManifest}},
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
				{Name: "ring", Version: "0.17.14", Kind: "runtime"},
				{Name: "openssl-src", Version: "300.5.0", Kind: "build"},
			}},
			want: []Candidate{
				{Name: "ring", Version: "0.17.14", Source: SourceManifest},
				{Name: "openssl-src", Version: "300.5.0", Source: SourceManifest},
			},
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
		"ring": {}, "sha2": {}, "openssl-src": {}, "aws-lc-rs": {}, "aws-lc-fips-sys": {}, "aws-lc-sys": {},
	}

	tests := []struct {
		name    string
		sbom    *Sbom
		symbols []string
		want    []Candidate
	}{
		{
			name:    "no manifest falls back to symbol backends",
			symbols: []string{"ring", "bundled-openssl"},
			want: []Candidate{
				{Name: "bundled-openssl", Source: SourceSymbol},
				{Name: "ring", Source: SourceSymbol},
			},
		},
		{
			name:    "manifest crate and its symbol backend dedup to one candidate",
			sbom:    &Sbom{Packages: []Package{{Name: "ring", Version: "0.17.14", Kind: "runtime"}}},
			symbols: []string{"ring"},
			want:    []Candidate{{Name: "ring", Version: "0.17.14", Source: SourceManifest}},
		},
		{
			name:    "precise fips crate suppresses the coarse aws-lc symbol",
			sbom:    &Sbom{Packages: []Package{{Name: "aws-lc-fips-sys", Version: "0.13.3", Kind: "build"}}},
			symbols: []string{"aws-lc"},
			want:    []Candidate{{Name: "aws-lc-fips-sys", Version: "0.13.3", Source: SourceManifest}},
		},
		{
			name:    "symbol backend with no manifest crate of its family is kept",
			sbom:    &Sbom{Packages: []Package{{Name: "serde", Kind: "runtime"}}},
			symbols: []string{"aws-lc"},
			want:    []Candidate{{Name: "aws-lc", Source: SourceSymbol}},
		},
		{
			name: "pure-Rust primitive from the manifest with no symbol",
			sbom: &Sbom{Packages: []Package{{Name: "sha2", Version: "0.10.8", Kind: "runtime"}}},
			want: []Candidate{{Name: "sha2", Version: "0.10.8", Source: SourceManifest}},
		},
		{
			name: "clean binary yields no candidate",
			sbom: &Sbom{Packages: []Package{{Name: "serde", Kind: "runtime"}}},
			want: nil,
		},
		{
			name: "aws-lc-rs wrapper folds into its fips backend, keeping the backend version",
			sbom: &Sbom{Packages: []Package{
				{Name: "aws-lc-rs", Version: "1.13.0", Kind: "runtime"},
				{Name: "aws-lc-fips-sys", Version: "0.13.3", Kind: "build"},
			}},
			symbols: []string{"aws-lc"},
			want:    []Candidate{{Name: "aws-lc-fips-sys", Version: "0.13.3", Source: SourceManifest}},
		},
		{
			name: "aws-lc-rs wrapper without its fips backend stays a candidate",
			sbom: &Sbom{Packages: []Package{{Name: "aws-lc-rs", Version: "1.13.0", Kind: "runtime"}}},
			want: []Candidate{{Name: "aws-lc-rs", Version: "1.13.0", Source: SourceManifest}},
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

func TestReadAuditableSectionRejectsOversizedSection(t *testing.T) {
	// A section that declares a size over the cap must be rejected before its
	// data is read, so a crafted header cannot force an allocation of that size.
	_, err := readAuditableSection(maxCompressed+1, failReader{t})
	require.ErrorContains(t, err, "over the")
}

func TestReadAuditableSectionParsesValidStream(t *testing.T) {
	want := &Sbom{Packages: []Package{{Name: "ring", Version: "0.17.14", Kind: "runtime"}}}
	raw := zlibJSON(t, want)
	got, err := readAuditableSection(uint64(len(raw)), bytes.NewReader(raw))
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestReadAuditableSectionCapsUnderstatedSize(t *testing.T) {
	// A section whose declared size is small but whose stream inflates past the
	// decompressed cap must fail on the cap, not read unbounded.
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, err := io.CopyN(zw, zeroReader{}, maxDecompressed+1)
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	_, err = readAuditableSection(1, &buf)
	require.ErrorContains(t, err, "exceeds")
}

func TestCommentHasRustc(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"rustc marker present among version strings", []byte("GCC: (GNU) 13.3.1\x00rustc version 1.80.0\x00"), true},
		{"no rust marker", []byte("GCC: (GNU) 13.3.1\x00clang version 17\x00"), false},
		{"marker within the cap is found", append(bytes.Repeat([]byte("x"), 1024), []byte("rustc")...), true},
		{"empty section", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, commentHasRustc(bytes.NewReader(tt.data)))
		})
	}
}

func TestCommentHasRustcBoundsTheRead(t *testing.T) {
	// A marker past the scan limit is not read, proving the prefix is bounded so
	// a crafted large .comment is never materialized whole.
	beyond := append(bytes.Repeat([]byte("x"), commentScanLimit), []byte("rustc")...)
	require.False(t, commentHasRustc(bytes.NewReader(beyond)))

	// An unbounded section consumes at most the cap, not its full declared size.
	cr := &countingReader{}
	require.False(t, commentHasRustc(cr))
	require.LessOrEqual(t, cr.n, commentScanLimit)
}

// countingReader is an infinite source of NUL bytes that records how much was read.
type countingReader struct{ n int }

func (c *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	c.n += len(p)
	return len(p), nil
}

// failReader fails the test if read; it proves the size guard short-circuits
// before touching section data.
type failReader struct{ t *testing.T }

func (f failReader) Read([]byte) (int, error) {
	f.t.Fatal("read attempted on an oversized section; size guard did not short-circuit")
	return 0, nil
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
