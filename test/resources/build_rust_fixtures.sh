#!/bin/bash
set -euo pipefail
# Build the Rust fixtures used by TestScanRealRustBinary. Needs a Rust
# toolchain plus cargo-auditable and crates.io access, so the fixtures are
# committed and the test skips when they are absent (check-payload CI has no
# Rust toolchain). Run this to regenerate them.
#
# Install: rustup, then `cargo install cargo-auditable`. Produces x86_64 ELF;
# the committed fixtures are arch-specific, so regenerate on the same arch.
#
# Fixture matrix (expected scanner verdict, with no Rust module attested):
#   ring-bin       ring runtime dep, cargo-auditable   (FAIL: provider not attested)
#   rustcrypto     pure-Rust sha2, no bundled backend  (FAIL: provider not attested)
#   clean          no crypto, cargo-auditable          (WARN: no provider, indeterminate)
#   clean-noaudit  no crypto, built without auditable  (WARN: no manifest)
#   ring-stripped  ring binary, .dep-v0 removed + strip (WARN: no provider detected)
#   ring-corrupt   ring binary, .dep-v0 overwritten     (FAIL: unparseable manifest)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/rust"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"
cd "$WORK"

mkcrate() { # name  dep-line  body
  cargo new --bin "$1" -q
  printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n%s\n' "$1" "$2" > "$1/Cargo.toml"
  printf '%s\n' "$3" > "$1/src/main.rs"
}

mkcrate ring-bin 'ring = "0.17"' 'fn main(){ let d = ring::digest::digest(&ring::digest::SHA256, b"x"); println!("{}", d.as_ref().len()); }'
mkcrate rustcrypto 'sha2 = "0.10"' 'use sha2::{Sha256,Digest}; fn main(){ let mut h=Sha256::new(); h.update(b"x"); println!("{:x}", h.finalize()); }'
mkcrate clean 'serde = "1"' 'fn main(){ println!("clean"); }'

build() { ( cd "$WORK/$1" && cargo auditable build --release -q && cp target/release/"$1" "$OUT/$1" ) ; }
build ring-bin
build rustcrypto
build clean

# clean built without cargo-auditable: no .dep-v0 section
( cd clean && cargo build --release -q && cp target/release/clean "$OUT/clean-noaudit" )

# evasion case: real bundled crypto, symbols stripped and manifest removed
cp "$OUT/ring-bin" "$OUT/ring-stripped"
objcopy --remove-section .dep-v0 "$OUT/ring-stripped"
strip "$OUT/ring-stripped"

# corrupt manifest: .dep-v0 replaced with non-zlib bytes
head -c 64 /dev/urandom > "$WORK/garbage.bin"
cp "$OUT/ring-bin" "$OUT/ring-corrupt"
objcopy --update-section .dep-v0="$WORK/garbage.bin" "$OUT/ring-corrupt"

echo "Built fixtures in $OUT:"
ls -la "$OUT"
