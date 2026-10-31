#!/bin/sh
# The stored RFC 9881 encoding of the ML-DSA private key in a PKCS#8 file,
# read without decoding the key (BTD-222): the first byte of the
# ML-DSA-PrivateKey CHOICE is 0x80 seed, 0x04 expanded or 0x30 both, the
# values of files[].ml_dsa_encoding. openssl pkcs8 and openssl pkey decode
# the key and encode it again, so they show a seed-only key as both.
#
#   misc/mldsa-key-encoding.sh <key file> [<password variable>]
#
# The file is PEM or DER, plain PKCS#8 or encrypted with PBES2
# (PBKDF2-HMAC-SHA256, AES-256-CBC) as bxc-pki export --format pkcs8 writes
# it. The password comes from the environment variable named by the second
# argument (default EXPORT_PASS), never from a command line. Prints one JSON
# object. Needs openssl (3.5 or later), python3 (encrypted files), dd, od.
set -eu

if [ $# -lt 1 ]; then
	sed -n '2,14p' "$0" >&2
	exit 2
fi
key=$1
var=${2:-EXPORT_PASS}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail() { echo "$key: $*" >&2; exit 1; }
# offset, header length and length of the n-th line matching $2 in $1
field() { grep "$2" "$1" | sed -n "${3}p"; }
pos() { echo "$1" | sed 's/^ *\([0-9]*\):.*/\1/'; }
hl() { echo "$1" | sed 's/.*hl= *\([0-9]*\).*/\1/'; }
len() { echo "$1" | sed 's/.* l= *\([0-9]*\).*/\1/'; }
hex() { echo "$1" | sed 's/.*\[HEX DUMP\]://'; }
# the content octets of an ASN.1 element, from its asn1parse line
content() {
	dd if="$1" of="$3" bs=1 skip=$(($(pos "$2") + $(hl "$2"))) \
		count="$(len "$2")" 2>/dev/null
}

form=DER
if grep -aq -- '-----BEGIN' "$key"; then
	form=PEM
fi
openssl asn1parse -inform "$form" -in "$key" -out "$tmp/p8" -noout ||
	fail "no ASN.1 structure"
openssl asn1parse -inform DER -in "$tmp/p8" > "$tmp/outer"

if grep -q 'OBJECT *:PBES2$' "$tmp/outer"; then
	for o in PBKDF2 hmacWithSHA256 aes-256-cbc; do
		grep -q "OBJECT *:$o\$" "$tmp/outer" ||
			fail "PBES2 without $o is not supported"
	done
	# PBES2 parameters in order: salt, iteration count, IV; then the
	# encrypted data
	salt=$(hex "$(field "$tmp/outer" 'OCTET STRING' 1)")
	iter=$(field "$tmp/outer" 'INTEGER' 1 | sed 's/.*://')
	iv=$(hex "$(field "$tmp/outer" 'OCTET STRING' 2)")
	content "$tmp/p8" "$(field "$tmp/outer" 'OCTET STRING' 3)" "$tmp/enc"
	eval "[ -n \"\${$var+x}\" ]" || fail "the password variable $var is not set"
	# openssl enc -pbkdf2 takes an 8 byte salt only and openssl kdf the
	# password only as an argument: PBKDF2 by Python, the password read
	# from the environment; only the key of this one file reaches the
	# openssl command line
	k=$(python3 -I -c 'import hashlib, os, sys
print(hashlib.pbkdf2_hmac("sha256", os.environb[sys.argv[1].encode()],
	bytes.fromhex(sys.argv[2]), int(sys.argv[3], 16), 32).hex())' \
		"$var" "$salt" "$iter") || fail "PBKDF2 failed"
	openssl enc -d -aes-256-cbc -K "$k" -iv "$iv" \
		-in "$tmp/enc" -out "$tmp/p8" 2>/dev/null ||
		fail "decryption failed (wrong password?)"
	openssl asn1parse -inform DER -in "$tmp/p8" > "$tmp/outer" ||
		fail "decryption failed (wrong password?)"
fi

alg=$(field "$tmp/outer" 'OBJECT' 1 | sed 's/.*OBJECT *://')
case "$alg" in
ML-DSA-*) ;;
*) fail "no ML-DSA private key: $alg" ;;
esac
content "$tmp/p8" "$(field "$tmp/outer" 'd=1 .*OCTET STRING' 1)" "$tmp/priv"
tag=$(od -An -tx1 -N1 "$tmp/priv" | tr -d ' \n')
case "$tag" in
80) enc=seed ;;
04) enc=expanded ;;
30) enc=both ;;
*) fail "unknown ML-DSA private key tag 0x$tag" ;;
esac
printf '{"file":"%s","algorithm":"%s","ml_dsa_encoding":"%s","tag":"0x%s"}\n' \
	"$key" "$alg" "$enc" "$tag"
