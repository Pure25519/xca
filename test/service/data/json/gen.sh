#!/bin/sh
# Generates the fixed fixtures of test/service/data/json (BTD-39), run once
set -eu
cd "$1"
O=openssl
$O version
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out device.key
$O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa-plain.key
$O pkcs8 -topk8 -v2 aes-256-cbc -in rsa-plain.key -passout pass:Import-Secret-11 -out rsa-enc.key
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out ec.key
$O genpkey -algorithm ED25519 -out own.key
$O pkey -in device.key -pubout -out device.pub

cat > ca.cnf <<'C'
[req]
distinguished_name = dn
prompt = no
utf8 = yes
string_mask = utf8only
[dn]
O = BxC Lab
CN = JSON Test CA
[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
C
$O req -new -x509 -key ca.key -config ca.cnf -extensions ca_ext -sha256 \
  -set_serial 0x4D2E8B19C07A35F1E6024B9D7C813A5F \
  -not_before 20261001000000Z -not_after 20361001000000Z -out ca.crt

cat > req.cnf <<'C'
[req]
distinguished_name = dn
attributes = attrs
req_extensions = req_ext
prompt = no
utf8 = yes
string_mask = utf8only
[dn]
O = BxC Lab
OU = Prüfstand
CN = plc11
[attrs]
challengePassword = Chall-Secret-42
unstructuredName = plc11 unit
[req_ext]
subjectAltName = URI:urn:bxc:plc11, DNS:plc11.lab
extendedKeyUsage = serverAuth, clientAuth
keyUsage = critical, digitalSignature, keyEncipherment
C
$O req -new -key device.key -config req.cnf -sha256 -out device.csr

cat > dev.ext <<'C'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = URI:urn:bxc:plc11, DNS:plc11.lab
authorityKeyIdentifier = keyid
subjectKeyIdentifier = hash
C
$O x509 -req -in device.csr -CA ca.crt -CAkey ca.key -sha256 \
  -set_serial 0xA1B2C3D4E5F60718293A4B5C6D7E8F90 \
  -not_before 20261028213542Z -not_after 20271028213542Z \
  -extfile dev.ext -out device.crt

mkdir -p cadb
printf 'R\t20271028213542Z\t261028213542Z,keyCompromise\tA1B2C3D4E5F60718293A4B5C6D7E8F90\tunknown\t/O=BxC Lab/OU=Pr\xC3\xBCfstand/CN=plc11\n' > cadb/index.txt
echo 01 > cadb/crlnumber
cat > crl.cnf <<'C'
[ca]
default_ca = CA_default
[CA_default]
dir = cadb
database = cadb/index.txt
crlnumber = cadb/crlnumber
certificate = ca.crt
private_key = ca.key
default_md = sha256
crl_extensions = crl_ext
[crl_ext]
authorityKeyIdentifier = keyid:always
C
$O ca -config crl.cnf -gencrl -crl_lastupdate 20261028213542Z -crl_nextupdate 20261104213542Z -out ca.crl
rm -rf cadb *.cnf dev.ext
$O crl -in ca.crl -noout -text
