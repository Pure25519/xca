# JSON forms bxc-pki inherits from lib/json_report (BTD-41, BTD-39 review
# MINOR 2 and 5): serials of legacy certificates (zero, negative, more
# than 20 octets; imported, never issued by bxc-pki) in the documented
# form; a private key read from a file reports storage "file" and its own
# protection, never "database"; request-cert with a key file stores only
# the request.

include("${LIB}")

bxc("create" 0 init --db "${DB}" ${PW} --cn "Forms Root")

# --- legacy serials ------------------------------------------------------
openssl_run(x genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256
    -out legacy.key)
set(long "0x0102030405060708090A0B0C0D0E0F101112131415161718")
foreach(case "zero|0|00" "negative|-10|-0A"
    "long|${long}|0102030405060708090A0B0C0D0E0F101112131415161718"
    "highbit|0x80FF|80FF")
  string(REPLACE "|" ";" parts "${case}")
  list(GET parts 0 name)
  list(GET parts 1 serial)
  list(GET parts 2 expect)
  openssl_run(x req -new -x509 -key legacy.key -subj "/CN=legacy-${name}"
      -days 30 -set_serial ${serial} -out "legacy-${name}.pem")
  bxc("show file ${name}" 0 show --file "legacy-${name}.pem")
  one_doc("show file ${name}" "${out}" certificate doc)
  string(JSON s GET "${doc}" serial)
  if(NOT s STREQUAL expect)
    fail("serial ${serial}: '${s}', expected '${expect}'")
  endif()
  xca_run("import ${name}" 0 --database "${DB}" ${PW} --import
      "${WORK}/legacy-${name}.pem")
  bxc("show stored ${name}" 0 show "legacy-${name}" --type certificate
      --db "${DB}" ${PW})
  one_doc("show stored ${name}" "${out}" certificate doc)
  string(JSON s GET "${doc}" serial)
  if(NOT s STREQUAL expect)
    fail("stored serial ${serial}: '${s}', expected '${expect}'")
  endif()
endforeach()
# the index of xca --json carries the same forms
xca_run("index" 0 --database "${DB}" ${PW} --json --index -)
foreach(want "\"serial\":\"00\"" "\"serial\":\"-0A\"" "\"serial\":\"80FF\"")
  string(FIND "${out}" "${want}" pos)
  if(pos EQUAL -1)
    fail("index: ${want} missing:\n${out}")
  endif()
endforeach()

# --- key files ---------------------------------------------------------
set(ENV{BXC_KEY_PW} "Key-File-Pw-1")
openssl_run(x genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256
    -out plain.key)
openssl_run(x pkcs8 -topk8 -v2 aes-256-cbc -in plain.key -out enc.key
    -passout env:BXC_KEY_PW)
openssl_run(x pkey -in plain.key -pubout -out pub.key)
foreach(case "plain.key|key_pair|none|" "enc.key|key_pair|own|--import-pass,env:BXC_KEY_PW"
    "pub.key|public_only||")
  string(REPLACE "|" ";" parts "${case}")
  list(GET parts 0 f)
  list(GET parts 1 kind)
  list(GET parts 2 prot)
  list(GET parts 3 extra)
  string(REPLACE "," ";" extra "${extra}")
  bxc("show ${f}" 0 show --file ${f} ${extra})
  one_doc("show ${f}" "${out}" key k)
  string(JSON st GET "${k}" storage)
  string(JSON pr GET "${k}" protection)
  string(JSON kd GET "${k}" kind)
  string(JSON id TYPE "${k}" id)
  if(NOT st STREQUAL "file" OR NOT pr STREQUAL prot OR NOT kd STREQUAL kind
     OR NOT id STREQUAL "NULL")
    fail("${f}: storage ${st}, protection ${pr}, kind ${kd}, id ${id}")
  endif()
endforeach()
# a key from an encrypted PKCS#12 file reports its own protection
openssl_run(x req -new -x509 -key plain.key -subj "/CN=p12" -days 30
    -out p12.crt)
openssl_run(x pkcs12 -export -in p12.crt -inkey plain.key -out enc.p12
    -passout env:BXC_KEY_PW)
bxc("show p12" 0 show --file enc.p12 --import-pass env:BXC_KEY_PW)
split_lines("${out}" docs)
set(seen FALSE)
foreach(d IN LISTS docs)
  string(JSON sch GET "${d}" schema)
  if(sch STREQUAL "urn:bxc-pki:schema:key:v1")
    string(JSON st GET "${d}" storage)
    string(JSON pr GET "${d}" protection)
    if(NOT st STREQUAL "file" OR NOT pr STREQUAL "own")
      fail("PKCS#12 key: storage ${st}, protection ${pr}")
    endif()
    set(seen TRUE)
  endif()
endforeach()
if(NOT seen)
  fail("show --file enc.p12: no key document:
${out}")
endif()

# stored keys keep "database"
bxc("show stored key" 0 show "Forms Root" --type key --db "${DB}" ${PW})
one_doc("show stored key" "${out}" key k)
string(JSON st GET "${k}" storage)
string(JSON pr GET "${k}" protection)
if(NOT st STREQUAL "database" OR NOT pr STREQUAL "database")
  fail("stored key: storage ${st}, protection ${pr}")
endif()

# request-cert with a key file: only the request is written
bxc("key file request" 0 request-cert --db "${DB}" ${PW} --cn filekey
    --key-file enc.key --import-pass env:BXC_KEY_PW)
one_doc("key file request" "${out}" cli-result r)
result_objects("${r}" objs)
if(NOT objs STREQUAL "request:filekey")
  fail("request-cert --key-file wrote '${objs}'")
endif()
object_doc("${r}" request csr)
string(JSON ki TYPE "${csr}" key_item)
if(NOT ki STREQUAL "NULL")
  fail("the key of a key file is not stored: key_item ${ki}")
endif()
bxc("key file missing pass" 1 request-cert --db "${DB}" ${PW} --cn filekey2
    --key-file enc.key)
expect_error("key file missing pass" missing_password)
if(NOT detail MATCHES "--import-pass")
  fail("missing --import-pass: ${detail}")
endif()
message(STATUS "bxc-pki JSON forms ok")
