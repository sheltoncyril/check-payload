// Package rust statically inspects Rust ELF binaries for FIPS validation.
package rust

import (
	"bytes"
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

// Decompression bounds for the untrusted .dep-v0 section, matching
// cargo-auditable's own limits (guarding against zip bombs).
const (
	maxCompressed   = 1 << 30 // 1 GiB on the section fed to the decompressor
	maxDecompressed = 8 << 20 // 8 MiB on the decompressed manifest
)

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

// IsRustExecutable reports whether the ELF was produced by rustc.
func IsRustExecutable(f *elf.File) bool {
	if f.Section(auditableSection) != nil {
		return true
	}
	if sect := f.Section(".comment"); sect != nil {
		if data, err := sect.Data(); err == nil && bytes.Contains(data, []byte("rustc")) {
			return true
		}
	}
	return false
}

// ReadAuditable returns the cargo-auditable manifest, or nil if absent.
func ReadAuditable(f *elf.File) (*Sbom, error) {
	sect := f.Section(auditableSection)
	if sect == nil {
		return nil, nil
	}
	if sect.Size > maxCompressed {
		return nil, fmt.Errorf("cargo-auditable section is %d bytes, over the %d limit", sect.Size, maxCompressed)
	}
	raw, err := sect.Data()
	if err != nil {
		return nil, err
	}
	return ParseAuditable(raw)
}

// ParseAuditable decodes the zlib-JSON of a cargo-auditable section.
func ParseAuditable(compressed []byte) (*Sbom, error) {
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
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

// nativeSourceCrates compile crypto into the runtime binary yet normally appear
// as build dependencies, so they are matched regardless of Cargo dependency kind.
var nativeSourceCrates = map[string]struct{}{
	"openssl-src": {}, "aws-lc-sys": {}, "aws-lc-fips-sys": {}, "boring-sys": {},
}

// LinkedCrypto returns denied crypto crates linked in. Build and dev deps are
// ignored except for native-source crates, which still link runtime crypto.
func (s *Sbom) LinkedCrypto(denied map[string]struct{}) []string {
	if s == nil {
		return nil
	}
	var found []string
	for _, p := range s.Packages {
		_, native := nativeSourceCrates[p.Name]
		if !native && p.Kind != "" && p.Kind != "runtime" {
			continue
		}
		if _, bad := denied[p.Name]; bad {
			found = append(found, p.Name)
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
