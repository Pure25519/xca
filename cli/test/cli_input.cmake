# Rules 4 and 12 of the certstrap triage in bxc-pki (BTD-41): --uri urn:,
# --email and a full RFC 4514 subject with a multi-valued RDN and DC; a
# URI-only request; invalid IP addresses and URIs are rejected; the CN is
# never filled from an IP address or URI; the RDN order is kept
# (openssl x509 -subject), directory strings are UTF8String.

include("${LIB}")

bxc("root" 0 init --db "${DB}" ${PW} --cn "Input Root")
one_doc("root" "${out}" cli-result r)
object_doc("${r}" certificate root)
pem_file("${root}" "${WORK}/root.pem")

# --- full DN, multi-valued RDN, DC, URI, email -------------------------
set(dn "CN=Prüfstand 7,OU=OT+O=BxC Lab,L=Köln,DC=lab,DC=example")
bxc("full dn" 0 request-cert --db "${DB}" ${PW} --subject "${dn}"
    --uri urn:bxc:lab:pruefstand7 --email ops@lab.example --name pruef7)
one_doc("full dn" "${out}" cli-result r)
object_doc("${r}" request csr)
extension("${csr}" subjectAltName san)
if(NOT san STREQUAL "URI:urn:bxc:lab:pruefstand7, email:ops@lab.example")
  fail("SAN: '${san}'")
endif()
if(san_critical)
  fail("SAN with a subject must not be critical")
endif()
bxc("sign full dn" 0 sign pruef7 --db "${DB}" ${PW} --ca "Input Root")
one_doc("sign full dn" "${out}" cli-result r)
object_doc("${r}" certificate crt)
pem_file("${crt}" "${WORK}/pruef7.pem")
openssl_run(subj x509 -in pruef7.pem -noout -subject -nameopt RFC2253,-esc_msb)
string(STRIP "${subj}" subj)
# DER sorts the values of a multi-valued RDN, so O and OU may swap
if(NOT subj STREQUAL "subject=${dn}" AND
   NOT subj STREQUAL "subject=CN=Prüfstand 7,O=BxC Lab+OU=OT,L=Köln,DC=lab,DC=example")
  fail("RDN order not kept: '${subj}'")
endif()
string(JSON j GET "${crt}" subject rfc4514)
if(NOT "subject=${j}" STREQUAL subj)
  fail("JSON subject '${j}' differs from openssl '${subj}'")
endif()
openssl_run(asn x509 -in pruef7.pem -noout -text)
openssl_run(parse asn1parse -in pruef7.pem)
foreach(want "UTF8STRING +:Prüfstand 7" "UTF8STRING +:BxC Lab"
    "UTF8STRING +:Köln" "IA5STRING +:lab" "IA5STRING +:example")
  if(NOT parse MATCHES "${want}")
    fail("subject string types (rule 12): '${want}' missing:\n${parse}")
  endif()
endforeach()
string(REGEX MATCH "X509v3 Subject Alternative Name:[^\n]*\n[^\n]*" sanx "${asn}")
if(NOT sanx MATCHES "URI:urn:bxc:lab:pruefstand7" OR NOT sanx MATCHES "email:ops@lab.example")
  fail("certificate SAN: ${sanx}")
endif()

# --- URI only: no subject, critical SAN, no CN -------------------------
bxc("uri only" 0 request-cert --db "${DB}" ${PW} --uri urn:bxc:lab:only)
one_doc("uri only" "${out}" cli-result r)
object_doc("${r}" request csr)
string(JSON n LENGTH "${csr}" subject attributes)
string(JSON name GET "${csr}" name)
if(NOT n EQUAL 0 OR NOT name STREQUAL "urn:bxc:lab:only")
  fail("URI-only request: ${n} subject attributes, name '${name}'")
endif()
extension("${csr}" subjectAltName san)
if(NOT san STREQUAL "URI:urn:bxc:lab:only" OR NOT san_critical)
  fail("URI-only request: SAN '${san}' critical '${san_critical}'")
endif()
bxc("sign uri only" 0 sign urn:bxc:lab:only --db "${DB}" ${PW}
    --ca "Input Root")
one_doc("sign uri only" "${out}" cli-result r)
object_doc("${r}" certificate crt)
string(JSON n LENGTH "${crt}" subject attributes)
extension("${crt}" subjectAltName san)
if(NOT n EQUAL 0 OR NOT san STREQUAL "URI:urn:bxc:lab:only" OR NOT san_critical)
  fail("URI-only certificate: ${n} attributes, SAN '${san}' (${san_critical})")
endif()
pem_file("${crt}" "${WORK}/only.pem")
openssl_run(v verify -CAfile root.pem only.pem)

# --- the CN never comes from an IP address or URI ------------------------
bxc("ip only" 0 request-cert --db "${DB}" ${PW} --ip 192.168.0.20
    --ip 2001:db8::20 --name ip-only)
one_doc("ip only" "${out}" cli-result r)
object_doc("${r}" request csr)
string(JSON n LENGTH "${csr}" subject attributes)
if(NOT n EQUAL 0)
  fail("a CN was derived from --ip: ${csr}")
endif()
extension("${csr}" subjectAltName san)
if(NOT san MATCHES "IP Address:192.168.0.20" OR NOT san MATCHES "IP Address:2001:DB8:0:0:0:0:0:20")
  fail("IP SAN: ${san}")
endif()
bxc("cn and uri" 0 request-cert --db "${DB}" ${PW} --cn device-a
    --uri urn:bxc:lab:device-a)
one_doc("cn and uri" "${out}" cli-result r)
object_doc("${r}" request csr)
string(JSON s GET "${csr}" subject rfc4514)
if(NOT s STREQUAL "CN=device-a")
  fail("subject '${s}'")
endif()

# --- strict checks ---------------------------------------------------------
foreach(case
    "invalid_ip|--ip;192.168.0.256" "invalid_ip|--ip;1.2.3"
    "invalid_ip|--ip;010.1.1.1" "invalid_ip|--ip;fe80::1%eth0"
    "invalid_ip|--ip;10.0.0.0/8" "invalid_ip|--ip;1:2:3:4:5:6:7:8:9"
    "invalid_ip|--ip;plc10.lab"
    "invalid_uri|--uri;not a uri" "invalid_uri|--uri;urn"
    "invalid_uri|--uri;http://" "invalid_uri|--uri;urn:bxc:x y"
    "invalid_uri|--uri;urn:a,DNS:b" "invalid_uri|--uri;urn:bxc:%zz"
    "invalid_uri|--uri;urn:bxc:ü"
    "invalid_dns|--dns;-bad.lab" "invalid_dns|--dns;192.168.0.1"
    "invalid_dns|--dns;a..b" "invalid_email|--email;no-at.example"
    "invalid_email|--email;a,b@x.example"
    "invalid_subject|--subject;CN" "invalid_subject|--subject;XX=y"
    "invalid_subject|--subject;CN=a,,O=b" "invalid_subject|--subject;CN=a<b"
    "invalid_subject|--subject;C=DEU" "invalid_subject|--subject;CN=#0403"
    "missing_option|--name;nothing")
  string(REPLACE "|" ";" parts "${case}")
  list(GET parts 0 code)
  list(SUBLIST parts 1 -1 args)
  bxc("${code}: ${args}" 2 request-cert --db "${DB}" ${PW} ${args})
  expect_error("${code}: ${args}" ${code})
endforeach()
# accepted forms
foreach(case "--dns;*.lab.example" "--ip;::1" "--ip;::ffff:192.0.2.1"
    "--uri;https://plc10.lab:4840/path?x=1#f" "--uri;urn:bxc:a%2Cb"
    "--subject;CN=a\\,b,O=x\\+y" "--subject;UID=u1,DC=lab"
    "--subject;2.5.4.3=oid-cn")
  string(REPLACE "|" ";" args "${case}")
  string(MD5 nm "${case}")
  bxc("accepted ${case}" 0 request-cert --db "${DB}" ${PW} ${args}
      --name "ok-${nm}")
endforeach()
bxc("escaped subject" 0 show "ok-${nm}" --type request --db "${DB}" ${PW})
message(STATUS "bxc-pki input ok")
