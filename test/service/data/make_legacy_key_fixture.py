#!/usr/bin/env python3
"""Makes schema8-legacy-keys.sql from schema8-fork.sql (BTD-269).

The fixture is a schema-8 fork database whose private keys are stored in the
legacy encryption of XCA 1.x, which XCA 2.0.0 to 2.4.x copied unconverted into
their SQL databases (upstream commit d32ab2e0, "Re-add support for legacy
keys"). The fork reads that format in pki_evp::legacyDecryptKey() and converts
it in db_key::updateKeyEncryptionScheme(). It is synthesised, not made by an
upstream build: the fork cannot convert an XCA 1.x database any more, and the
last upstream SQL build before PKCS#8 (d50dbbd7) used SHA-256 with 8000 rounds,
which legacyDecryptKey() does not read (BTD-269 AI Info).

The legacy blob of a key, exactly as legacyDecryptKey() reads it:

    blob = iv || 3DES-EDE-CBC(key, iv, PKCS#7 padding)(i2d_PrivateKey(pkey))
    key  = EVP_BytesToKey(des-ede3-cbc, SHA-1, salt = iv, password, count 1)

with an 8-byte iv, the database password as password, and the type-specific
DER (SEC1 for EC, PKCS#1 for RSA) as plaintext.

Input: schema8-fork.sql (service-test-db-pass, see README.md). Each private
key there (PKCS#8, encrypted with the database password) is decrypted with the
openssl program and encrypted again in the legacy format with a fixed iv per
item, so the output is byte-reproducible. The settings row legacy-keys-updated
is left out, as in a database that was never converted.

Usage: make_legacy_key_fixture.py [--openssl PROGRAM] SOURCE.sql OUTPUT.sql
"""

import argparse
import base64
import hashlib
import re
import subprocess
import sys

PASSWORD = b"service-test-db-pass"
# a fixed iv per item id of schema8-fork.sql: byte-reproducible output
IVS = {
    1: bytes.fromhex("0102030405060708"),
    3: bytes.fromhex("1112131415161718"),
}
ROW = re.compile(r"^INSERT INTO \"private_keys\" VALUES\((\d+),0,'([^']+)'\);$")


def bytes_to_key(password, salt, key_len=24, iv_len=8):
    """OpenSSL EVP_BytesToKey() with SHA-1 and count 1"""
    out, prev = b"", b""
    while len(out) < key_len + iv_len:
        prev = hashlib.sha1(prev + password + salt).digest()
        out += prev
    return out[:key_len]


def openssl(program, args, data):
    r = subprocess.run([program] + args, input=data, capture_output=True,
                       check=False)
    if r.returncode != 0:
        sys.exit("openssl %s failed: %s" % (" ".join(args),
                                            r.stderr.decode(errors="replace")))
    return r.stdout


def legacy_blob(program, pkcs8_b64, iv):
    pkcs8 = base64.b64decode(pkcs8_b64)
    plain = openssl(program, ["pkcs8", "-inform", "DER", "-passin",
                              "pass:" + PASSWORD.decode(), "-traditional",
                              "-outform", "DER"], pkcs8)
    key = bytes_to_key(PASSWORD, iv)
    cipher = openssl(program, ["enc", "-des-ede3-cbc", "-K", key.hex(),
                               "-iv", iv.hex(), "-nosalt"], plain)
    return base64.b64encode(iv + cipher).decode()


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--openssl", default="openssl")
    p.add_argument("source")
    p.add_argument("output")
    a = p.parse_args()

    out, done = [], set()
    with open(a.source, encoding="utf-8", newline="") as f:
        for line in f:
            text = line.rstrip("\r\n")
            m = ROW.match(text)
            if m:
                item = int(m.group(1))
                if item not in IVS:
                    sys.exit("no iv for private key item %d" % item)
                blob = legacy_blob(a.openssl, m.group(2), IVS[item])
                line = "INSERT INTO \"private_keys\" VALUES(%d,0,'%s');\n" \
                       % (item, blob)
                done.add(item)
            elif text == "INSERT INTO \"settings\" VALUES('legacy-keys-updated','yes');":
                continue
            out.append(line)
    if done != set(IVS):
        sys.exit("private keys converted: %s, expected %s"
                 % (sorted(done), sorted(IVS)))
    with open(a.output, "w", encoding="utf-8", newline="") as f:
        f.writelines(out)


if __name__ == "__main__":
    main()
