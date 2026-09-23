// Package rust statically inspects Rust ELF binaries for FIPS validation.
package rust

import (
	"bytes"
	"cmp"
	"compress/zlib"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

// auditableSection holds cargo-auditable's zlib-compressed JSON crate list.
const auditableSection = ".dep-v0"

// Bounds for the untrusted .dep-v0 section. Real manifests are a few KB; both
// caps are deliberately generous while keeping a crafted section from forcing a
// large read. The section is read through a bounded stream, so its declared size
// is never trusted to allocate.
const (
	maxCompressed   = 8 << 20 // 8 MiB on the raw section fed to the decompressor
	maxDecompressed = 8 << 20 // 8 MiB on the decompressed manifest
)

// commentScanLimit bounds the .comment read for the rustc producer marker.
// .comment holds NUL-separated compiler version strings and is tiny in practice;
// the marker sits at the start, so a bounded prefix does not miss a real Rust
// binary while a crafted large section is capped rather than read whole.
const commentScanLimit = 64 << 10 // 64 KiB

// Package is one crate from the cargo-auditable manifest.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Kind is "runtime" (the default when empty), "build", or "development".
	Kind string `json:"kind"`
}

// Sbom is the cargo-auditable dependency manifest.
type Sbom struct {
	Packages []Package `json:"packages"`
}

// IsRustExecutable reports whether the ELF was produced by rustc. It is a
// best-effort producer heuristic, not an adversarial boundary: a stripped or
// crafted binary can defeat it and fall to the regular-executable arm.
func IsRustExecutable(f *elf.File) bool {
	if f.Section(auditableSection) != nil {
		return true
	}
	if sect := f.Section(".comment"); sect != nil {
		return commentHasRustc(sect.Open())
	}
	return false
}

// commentHasRustc reports whether the rustc producer marker appears in the
// bounded prefix of a .comment section, so a crafted large section is not read
// whole.
func commentHasRustc(r io.Reader) bool {
	data, err := io.ReadAll(io.LimitReader(r, commentScanLimit))
	return err == nil && bytes.Contains(data, []byte("rustc"))
}

// ReadAuditable returns the cargo-auditable manifest, or nil if absent.
func ReadAuditable(f *elf.File) (*Sbom, error) {
	sect := f.Section(auditableSection)
	if sect == nil {
		return nil, nil
	}
	return readAuditableSection(sect.Size, sect.Open())
}

// readAuditableSection reads a .dep-v0 section through a bounded stream. The
// declared size is checked first, then the stream itself is capped, so a crafted
// section header cannot force an allocation of its declared size before the
// decompression bound applies.
func readAuditableSection(size uint64, r io.Reader) (*Sbom, error) {
	if size > maxCompressed {
		return nil, fmt.Errorf("cargo-auditable section is %d bytes, over the %d limit", size, maxCompressed)
	}
	return parseAuditableStream(io.LimitReader(r, maxCompressed))
}

// ParseAuditable decodes the zlib-JSON of a cargo-auditable section.
func ParseAuditable(compressed []byte) (*Sbom, error) {
	return parseAuditableStream(bytes.NewReader(compressed))
}

// parseAuditableStream decodes zlib-JSON from a reader, bounding the decompressed
// output so a small compressed stream cannot inflate without limit.
func parseAuditableStream(r io.Reader) (*Sbom, error) {
	zr, err := zlib.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	decompressed, err := io.ReadAll(io.LimitReader(zr, maxDecompressed+1))
	if err != nil {
		return nil, err
	}
	if len(decompressed) > maxDecompressed {
		return nil, fmt.Errorf("cargo-auditable manifest exceeds the %d byte limit", maxDecompressed)
	}
	var sbom Sbom
	if err := json.Unmarshal(decompressed, &sbom); err != nil {
		return nil, err
	}
	return &sbom, nil
}

// nativeSourceCrates link runtime crypto but appear as build deps, so kind is ignored.
var nativeSourceCrates = map[string]struct{}{
	"openssl-src": {}, "aws-lc-sys": {}, "aws-lc-fips-sys": {}, "boring-sys": {},
}

// backendFamilies maps a symbol backend to same-provider crate names. A symbol
// backend is dropped when the manifest already names a crate in its family.
var backendFamilies = map[string][]string{
	"aws-lc":          {"aws-lc-rs", "aws-lc-sys", "aws-lc-fips-sys"},
	"boringssl":       {"boring", "boring-sys"},
	"bundled-openssl": {"openssl-src"},
	"ring":            {"ring"},
}

// candidateSource records how a crypto candidate was detected.
const (
	SourceManifest = "manifest" // named in the cargo-auditable crate list, carries a version
	SourceSymbol   = "symbol"   // inferred from a defined ELF symbol, no version
)

// Candidate is a bundled crypto provider detected in a binary, with the version
// and evidence source used to attest it. Version is empty for symbol backends.
type Candidate struct {
	Name    string
	Version string
	Source  string
}

// wrapperBackends folds a wrapper crate into the backend that carries the
// provider identity when both are present. aws-lc-rs built with features=["fips"]
// pulls aws-lc-fips-sys; the fips backend is the authoritative FIPS provider and
// carries the version, so the ambiguous wrapper is dropped in its favor. A
// wrapper seen without its fips backend stays a candidate and must be attested.
var wrapperBackends = map[string]string{
	"aws-lc-rs": "aws-lc-fips-sys",
}

// CryptoModuleCandidates names the bundled crypto providers a binary carries, as
// candidates the certified-module path can attest. Manifest crates win over the
// coarser symbol backends, and a wrapper crate folds into its FIPS backend.
func CryptoModuleCandidates(sbom *Sbom, denied map[string]struct{}, symbolBackends []string) []Candidate {
	crates := sbom.LinkedCrypto(denied)
	out := slices.Clone(crates)
	for _, backend := range symbolBackends {
		if !familyNamed(backendFamilies[backend], crates) {
			out = append(out, Candidate{Name: backend, Source: SourceSymbol})
		}
	}
	out = collapseWrappers(out)
	slices.SortFunc(out, func(a, b Candidate) int {
		return cmp.Or(
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.Version, b.Version),
			cmp.Compare(a.Source, b.Source),
		)
	})
	return slices.Compact(out)
}

// collapseWrappers drops a wrapper crate when its FIPS backend is also present,
// so the combined evidence maps to a single provider identity.
func collapseWrappers(candidates []Candidate) []Candidate {
	present := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		present[c.Name] = struct{}{}
	}
	return slices.DeleteFunc(candidates, func(c Candidate) bool {
		backend, ok := wrapperBackends[c.Name]
		if !ok {
			return false
		}
		_, hasBackend := present[backend]
		return hasBackend
	})
}

// familyNamed reports whether any candidate names a crate in the family, so a
// coarse symbol backend is dropped when the manifest already names its provider.
func familyNamed(family []string, candidates []Candidate) bool {
	return slices.ContainsFunc(candidates, func(c Candidate) bool {
		return slices.Contains(family, c.Name)
	})
}

// LinkedCrypto returns denied crypto crates linked in, with their manifest
// versions. Build and dev deps are ignored except for native-source crates,
// which still link runtime crypto.
func (s *Sbom) LinkedCrypto(denied map[string]struct{}) []Candidate {
	if s == nil {
		return nil
	}
	var found []Candidate
	for _, p := range s.Packages {
		_, native := nativeSourceCrates[p.Name]
		if !native && p.Kind != "" && p.Kind != "runtime" {
			continue
		}
		if _, bad := denied[p.Name]; bad {
			found = append(found, Candidate{Name: p.Name, Version: p.Version, Source: SourceManifest})
		}
	}
	return found
}

// cryptoBackends maps a defined-symbol prefix to the backend it names. ring is
// first so ring's own OPENSSL_ symbols attribute to ring rather than a bundled OpenSSL.
var cryptoBackends = []struct {
	prefix  string
	backend string
}{
	{"ring_core_", "ring"},
	{"GFp_", "ring"}, // ring 0.16-era
	{"BORINGSSL_", "boringssl"},
	{"aws_lc_", "aws-lc"},
	{"AWSLC_", "aws-lc"},
	{"OPENSSL_", "bundled-openssl"},
}

// cryptoBackendForSymbol returns the backend a symbol name identifies, if any.
func cryptoBackendForSymbol(name string) (string, bool) {
	for _, c := range cryptoBackends {
		if strings.HasPrefix(name, c.prefix) {
			return c.backend, true
		}
	}
	return "", false
}

// BundledCryptoBackends returns the bundled crypto backends whose defined symbols
// appear in the binary. Undefined imports (system libcrypto) are skipped.
func BundledCryptoBackends(f *elf.File) []string {
	var backends []string
	if syms, err := f.Symbols(); err == nil {
		backends = append(backends, definedCryptoBackends(syms)...)
	}
	if syms, err := f.DynamicSymbols(); err == nil {
		backends = append(backends, definedCryptoBackends(syms)...)
	}
	slices.Sort(backends)
	return slices.Compact(backends)
}

// definedCryptoBackends returns backends named by defined symbols, dups kept.
func definedCryptoBackends(syms []elf.Symbol) []string {
	var found []string
	for i := range syms {
		if syms[i].Section == elf.SHN_UNDEF {
			continue
		}
		if backend, ok := cryptoBackendForSymbol(syms[i].Name); ok {
			found = append(found, backend)
		}
	}
	return found
}
