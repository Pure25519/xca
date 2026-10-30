# --key of bxc-pki (BTD-41, boss decision 2026-10-29): exactly the key
# type names of the bootstrap file (bxc-pki schemas/bootstrap.schema.json
# $defs/keyType); every name generates the key it names; --help lists the
# available ones; an EdDSA and an ML-DSA CA sign, the chains verify.

include("${LIB}")

# name|JSON public_key.type|size or curve
set(types
  "rsa-2048|RSA|2048" "rsa-3072|RSA|3072" "rsa-4096|RSA|4096"
  "ec-p256|EC|prime256v1" "ec-p384|EC|secp384r1" "ec-p521|EC|secp521r1"
  "ec-brainpoolp256r1|EC|brainpoolP256r1"
  "ec-brainpoolp384r1|EC|brainpoolP384r1"
  "ec-brainpoolp512r1|EC|brainpoolP512r1"
  "ed25519|ED25519|" "ed448|ED448|"
  "ml-dsa-44|ML-DSA-44|" "ml-dsa-65|ML-DSA-65|" "ml-dsa-87|ML-DSA-87|"
  "slh-dsa-sha2-128s|SLH-DSA-SHA2-128s|" "slh-dsa-sha2-128f|SLH-DSA-SHA2-128f|"
  "slh-dsa-sha2-192s|SLH-DSA-SHA2-192s|" "slh-dsa-sha2-192f|SLH-DSA-SHA2-192f|"
  "slh-dsa-sha2-256s|SLH-DSA-SHA2-256s|" "slh-dsa-sha2-256f|SLH-DSA-SHA2-256f|"
  "slh-dsa-shake-128s|SLH-DSA-SHAKE-128s|" "slh-dsa-shake-128f|SLH-DSA-SHAKE-128f|"
  "slh-dsa-shake-192s|SLH-DSA-SHAKE-192s|" "slh-dsa-shake-192f|SLH-DSA-SHAKE-192f|"
  "slh-dsa-shake-256s|SLH-DSA-SHAKE-256s|" "slh-dsa-shake-256f|SLH-DSA-SHAKE-256f|")

bxc("help" 0 request-cert --help)
set(help "${out}")
bxc("root" 0 init --db "${DB}" ${PW} --cn "Types Root" --key rsa-3072)
foreach(t IN LISTS types)
  string(REPLACE "|" ";" parts "${t}")
  list(GET parts 0 name)
  list(GET parts 1 jtype)
  list(GET parts 2 param)
  string(FIND "${help}" "${name}" pos)
  if(pos EQUAL -1)
    fail("--help does not list ${name}:\n${help}")
  endif()
  bxc("request ${name}" 0 request-cert --db "${DB}" ${PW} --cn "kt-${name}"
      --key ${name})
  one_doc("request ${name}" "${out}" cli-result r)
  object_doc("${r}" key k)
  string(JSON pt GET "${k}" public_key type)
  string(JSON size GET "${k}" public_key size)
  string(JSON curve ERROR_VARIABLE noc GET "${k}" public_key curve name)
  if(NOT pt STREQUAL jtype)
    fail("${name}: key type ${pt}, expected ${jtype}")
  endif()
  if(jtype STREQUAL "RSA" AND NOT size STREQUAL param)
    fail("${name}: ${size} bit")
  endif()
  if(jtype STREQUAL "EC" AND NOT curve STREQUAL param)
    fail("${name}: curve ${curve}")
  endif()
  object_doc("${r}" request csr)
  pem_file("${csr}" "${WORK}/${name}.csr")
  openssl_run(v req -in "${name}.csr" -noout -verify)
endforeach()

# CAs with EdDSA and ML-DSA keys sign (no digest of their own)
foreach(ca ed25519 ed448 ml-dsa-65)
  bxc("ca ${ca}" 0 init --db "${DB}" ${PW} --cn "CA ${ca}" --key ${ca})
  one_doc("ca ${ca}" "${out}" cli-result r)
  object_doc("${r}" certificate cacrt)
  pem_file("${cacrt}" "${WORK}/ca-${ca}.pem")
  bxc("sign by ${ca}" 0 sign kt-ec-p256 --db "${DB}" ${PW} --ca "CA ${ca}"
      --name "ee-${ca}")
  one_doc("sign by ${ca}" "${out}" cli-result r)
  object_doc("${r}" certificate ee)
  pem_file("${ee}" "${WORK}/ee-${ca}.pem")
  openssl_run(v verify -CAfile "ca-${ca}.pem" "ee-${ca}.pem")
endforeach()
message(STATUS "bxc-pki key types ok")
