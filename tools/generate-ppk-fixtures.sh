#!/usr/bin/env bash
# Regenerates the PuTTY key fixtures used by tests/unit/PpkConverterTests.cpp.
#
# The keys are produced by PuTTY's own puttygen, an implementation independent
# of the converter under test, and are throwaway test material only.
#
# Usage (Linux or WSL with putty-tools installed):
#   tools/generate-ppk-fixtures.sh [output-dir]
set -euo pipefail

out="${1:-$(dirname "$0")/../tests/fixtures/ppk}"
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

: > "$work/empty"
printf '%s' 'correct horse battery staple' > "$work/pass"
cp "$work/pass" "$out/passphrase.txt"

# name | puttygen -t/-b | KDF parameters for the encrypted format-3 variant
specs=(
  "rsa2048|-t rsa -b 2048|kdf=argon2id,memory=8192,passes=2,parallel=1"
  "ecdsa256|-t ecdsa -b 256|kdf=argon2i,memory=8192,passes=3,parallel=1"
  "ecdsa384|-t ecdsa -b 384|kdf=argon2d,memory=4096,passes=2,parallel=1"
  "ecdsa521|-t ecdsa -b 521|kdf=argon2id,memory=16384,passes=1,parallel=2"
  "ed25519|-t ed25519|kdf=argon2id,memory=8192,passes=4,parallel=4"
)

for spec in "${specs[@]}"; do
  IFS='|' read -r name keygen kdf <<< "$spec"
  base="$work/$name.ppk"
  # shellcheck disable=SC2086
  puttygen $keygen -C "SFTPplug test fixture $name - not a real key" \
           --new-passphrase "$work/empty" -o "$base"

  puttygen "$base" -O public-openssh -o "$out/$name.pub"
  # puttygen writes format 3, unencrypted, by default: the base is that variant.
  cp "$base" "$out/$name-v3-none.ppk"
  # Changing only the file format needs --reencrypt to count as an action.
  puttygen "$base" -O private --reencrypt --ppk-param version=2 -o "$out/$name-v2-none.ppk"
  # -P requests the passphrase change; --new-passphrase only supplies it.
  puttygen "$base" -O private -P --new-passphrase "$work/pass" --ppk-param "version=3,$kdf" -o "$out/$name-v3-enc.ppk"
  puttygen "$base" -O private -P --new-passphrase "$work/pass" --ppk-param version=2 -o "$out/$name-v2-enc.ppk"
done

echo "fixtures written to $out"
