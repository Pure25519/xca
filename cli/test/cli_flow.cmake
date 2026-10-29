# bxc-pki end to end (BTD-41): init root, init intermediate --parent,
# request-cert with --ip and --dns, sign, list, show on a fresh database;
# the chain verifies with openssl verify; pathLen 0 vs absent (rule 1);
# serials (rule 2); KU/EKU only from the template, a custom EKU OID,
# no keyEncipherment for EC/EdDSA by default (rule 3); every command
# writes audit entries with channel cli and the chain verifies; the
# binary needs no Qt Gui, Widgets or Help (ldd recorded); --help
# documents every command and option.

include("${LIB}")

# --- root, intermediate, end entity -----------------------------------
bxc("init root" 0 init --db "${DB}" ${PW} --cn "BxC Lab Root"
    --validity P10Y)
one_doc("init root" "${out}" cli-result root)
result_objects("${root}" objs)
if(NOT objs STREQUAL "key:BxC Lab Root;certificate:BxC Lab Root")
  fail("init root wrote '${objs}'")
endif()
object_doc("${root}" certificate root_crt)
string(JSON capped GET "${root_crt_entry}" validity_capped)
if(capped)
  fail("root: validity_capped must be false")
endif()
extension("${root_crt}" basicConstraints bc)
if(NOT bc STREQUAL "CA:TRUE" OR NOT bc_critical)
  fail("root: basicConstraints '${bc}', expected critical CA:TRUE without pathlen (rule 1)")
endif()
if(NOT err STREQUAL "")
  fail("init root: unexpected stderr:\n${err}")
endif()

bxc("init intermediate" 0 init --db "${DB}" ${PW} --cn "BxC Lab Issuing"
    --parent "BxC Lab Root" --path-len 0 --key-type rsa:3072 --validity P5Y)
one_doc("init intermediate" "${out}" cli-result inter)
object_doc("${inter}" certificate int_crt)
extension("${int_crt}" basicConstraints bc)
if(NOT bc MATCHES "^CA:TRUE, pathlen:0$")
  fail("intermediate: basicConstraints '${bc}', expected CA:TRUE, pathlen:0")
endif()
string(JSON issuer GET "${int_crt}" issuer_item name)
if(NOT issuer STREQUAL "BxC Lab Root")
  fail("intermediate: issuer '${issuer}'")
endif()

bxc("request-cert" 0 request-cert --db "${DB}" ${PW} --cn plc10
    --ip 192.168.0.10 --dns plc10.lab)
one_doc("request-cert" "${out}" cli-result reqres)
result_objects("${reqres}" objs)
if(NOT objs STREQUAL "key:plc10;request:plc10")
  fail("request-cert wrote '${objs}'")
endif()
object_doc("${reqres}" request csr)
extension("${csr}" subjectAltName san)
if(NOT san MATCHES "IP Address:192.168.0.10" OR NOT san MATCHES "DNS:plc10.lab")
  fail("request: SAN '${san}'")
endif()
extension("${csr}" keyUsage ku)
extension("${csr}" extendedKeyUsage eku)
if(ku OR eku)
  fail("request: no KU/EKU expected (rule 3), got '${ku}' '${eku}'")
endif()

bxc("sign" 0 sign plc10 --db "${DB}" ${PW} --ca "BxC Lab Issuing"
    --validity P1Y)
one_doc("sign" "${out}" cli-result signed)
result_objects("${signed}" objs)
if(NOT objs STREQUAL "certificate:plc10")
  fail("sign wrote '${objs}'")
endif()
object_doc("${signed}" certificate ee_crt)
extension("${ee_crt}" subjectAltName san)
if(NOT san MATCHES "IP Address:192.168.0.10" OR NOT san MATCHES "DNS:plc10.lab")
  fail("certificate: SAN '${san}' not taken from the request")
endif()
extension("${ee_crt}" keyUsage ku)
if(NOT ku STREQUAL "Digital Signature")
  fail("EC certificate: keyUsage '${ku}', expected Digital Signature only (rule 3)")
endif()
extension("${ee_crt}" extendedKeyUsage eku)
if(eku)
  fail("certificate without template: no EKU expected (rule 3), got '${eku}'")
endif()

# --- chain with openssl verify ----------------------------------------
pem_file("${root_crt}" "${WORK}/root.pem")
pem_file("${int_crt}" "${WORK}/int.pem")
pem_file("${ee_crt}" "${WORK}/plc10.pem")
openssl_run(v verify -CAfile root.pem -untrusted int.pem plc10.pem)
if(NOT v MATCHES "plc10.pem: OK")
  fail("openssl verify: ${v}")
endif()
openssl_run(v verify -CAfile root.pem int.pem)

# --- Ed25519 and RSA end entities, custom EKU from a template ------------
bxc("request ed25519" 0 request-cert --db "${DB}" ${PW} --cn ed-dev
    --dns ed-dev.lab --key-type ed25519)
bxc("sign ed25519" 0 sign ed-dev --db "${DB}" ${PW} --ca "BxC Lab Issuing")
one_doc("sign ed25519" "${out}" cli-result r)
object_doc("${r}" certificate ed_crt)
extension("${ed_crt}" keyUsage ku)
if(ku MATCHES "Encipherment")
  fail("Ed25519 certificate with '${ku}' (rule 3)")
endif()
bxc("request rsa" 0 request-cert --db "${DB}" ${PW} --cn rsa-dev
    --key-type rsa:2048)
bxc("sign rsa" 0 sign rsa-dev --db "${DB}" ${PW} --ca "BxC Lab Issuing")
one_doc("sign rsa" "${out}" cli-result r)
object_doc("${r}" certificate rsa_crt)
extension("${rsa_crt}" keyUsage ku)
if(NOT ku STREQUAL "Digital Signature, Key Encipherment")
  fail("RSA certificate: keyUsage '${ku}'")
endif()

execute_process(COMMAND "${FIXTURE}" "${DB}" env:BXC_DB_PW template
    custom-eku "serverAuth,1.3.6.1.4.1.55555.7.1" digitalSignature
  RESULT_VARIABLE r ERROR_VARIABLE e)
if(NOT r EQUAL 0)
  fail("cli_fixture template: ${e}")
endif()
bxc("request eku" 0 request-cert --db "${DB}" ${PW} --cn eku-dev
    --dns eku-dev.lab)
bxc("sign template" 0 sign eku-dev --db "${DB}" ${PW}
    --ca "BxC Lab Issuing" --template custom-eku)
one_doc("sign template" "${out}" cli-result r)
object_doc("${r}" certificate eku_crt)
extension("${eku_crt}" extendedKeyUsage eku)
if(NOT eku STREQUAL "TLS Web Server Authentication, 1.3.6.1.4.1.55555.7.1")
  fail("EKU from the template: '${eku}'")
endif()
string(JSON subj GET "${eku_crt}" subject rfc4514)
if(NOT subj STREQUAL "CN=eku-dev")
  fail("template must not replace the request subject: '${subj}'")
endif()
extension("${eku_crt}" subjectAltName san)
if(NOT san STREQUAL "DNS:eku-dev.lab")
  fail("template sign: SAN '${san}'")
endif()

# --- serials (rule 2) -------------------------------------------------
set(serials "")
foreach(d root_crt int_crt ee_crt ed_crt rsa_crt eku_crt)
  string(JSON s GET "${${d}}" serial)
  # 9..20 octets, first octet 01..7F: positive, >= 64 random bits
  if(NOT s MATCHES "^[0-7][0-9A-F]([0-9A-F][0-9A-F])+$" OR s MATCHES "^00")
    fail("${d}: serial '${s}' breaks rule 2")
  endif()
  string(LENGTH "${s}" len)
  if(len LESS 18 OR len GREATER 40)
    fail("${d}: serial '${s}' has ${len} hex digits")
  endif()
  if(s IN_LIST serials)
    fail("serial ${s} issued twice")
  endif()
  list(APPEND serials "${s}")
endforeach()

# --- list and show ------------------------------------------------------
bxc("list" 0 list --db "${DB}" ${PW})
one_doc("list" "${out}" list l)
string(JSON n LENGTH "${l}" items)
# 2 CAs (key + cert), 4 end entities (key + request + cert), 1 template
if(NOT n EQUAL 17)
  fail("list: ${n} items, expected 17:\n${l}")
endif()
bxc("list certificates" 0 list --db "${DB}" ${PW} --type certificate)
one_doc("list certificates" "${out}" list l)
string(JSON n LENGTH "${l}" items)
if(NOT n EQUAL 6)
  fail("list --type certificate: ${n} items")
endif()
bxc("list without password" 0 list --db "${DB}")
one_doc("list without password" "${out}" list l)

string(JSON id GET "${ee_crt}" id)
bxc("show by id" 0 show ${id} --db "${DB}" ${PW})
one_doc("show by id" "${out}" certificate shown)
string(JSON sn GET "${shown}" serial)
string(JSON sn0 GET "${ee_crt}" serial)
if(NOT sn STREQUAL sn0)
  fail("show ${id}: serial ${sn}, expected ${sn0}")
endif()
bxc("show ambiguous" 1 show plc10 --db "${DB}" ${PW})
expect_error("show ambiguous" ambiguous_reference)
if(NOT detail MATCHES "key [0-9]+ 'plc10'" OR
   NOT detail MATCHES "request [0-9]+ 'plc10'" OR
   NOT detail MATCHES "certificate [0-9]+ 'plc10'")
  fail("ambiguous name must list the candidates: ${detail}")
endif()
bxc("show by name and type" 0 show plc10 --type request --db "${DB}" ${PW})
one_doc("show by name and type" "${out}" csr x)
bxc("show text" 0 show ${id} --text --db "${DB}" ${PW})
if(NOT out MATCHES "Certificate:" OR NOT err STREQUAL "")
  fail("show --text: ${out}${err}")
endif()

# --- audit: channel cli, chain intact ----------------------------------
audit_entries(lines)
split_lines("${lines}" lines)
set(actions "")
foreach(line IN LISTS lines)
  string(JSON action GET "${line}" action)
  string(JSON channel GET "${line}" channel)
  string(JSON actor GET "${line}" actor)
  if(action MATCHES "^(key\\.generate|certificate\\.issue|request\\.create)$")
    if(NOT channel STREQUAL "cli" OR NOT actor MATCHES "^os:")
      fail("audit entry ${action}: channel '${channel}', actor '${actor}'")
    endif()
    list(APPEND actions "${action}")
  endif()
endforeach()
list(FILTER actions INCLUDE REGEX "key.generate")
list(LENGTH actions keys)
if(NOT keys EQUAL 6)
  fail("expected 6 key.generate entries, got ${keys}")
endif()

# --- no Qt Gui, Widgets or Help; --help -------------------------------
if(LDD AND EXISTS "${LDD}")
  execute_process(COMMAND "${LDD}" "${BXC_PKI}" OUTPUT_VARIABLE ldd)
  file(WRITE "${WORK}/ldd.txt" "${ldd}")
  if(ldd MATCHES "libQt[0-9]*(Gui|Widgets|Help)")
    fail("bxc-pki links ${CMAKE_MATCH_0}:\n${ldd}")
  endif()
  if(NOT ldd MATCHES "libQt[0-9]*Core")
    fail("ldd shows no Qt Core: the check is broken\n${ldd}")
  endif()
endif()
bxc("help" 0 --help)
foreach(word init request-cert sign list show
    --db --password --sqlpass --import-pass --export-pass --pin --so-pin
    --new-pin --new-so-pin --interactive --text --plan --help --cn
    --subject --name --parent --path-len --key-type --key --key-file
    --validity --not-before --not-after --backdate --hash --dns --ip
    --uri --email --ca --template --profile --type --file
    rsa ec ed25519)
  string(FIND "${out}" "${word}" pos)
  if(pos EQUAL -1)
    fail("--help does not document '${word}'")
  endif()
endforeach()
message(STATUS "bxc-pki flow ok")
