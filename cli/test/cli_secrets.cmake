# Secrets of bxc-pki (BTD-41, BTD-30 side findings 4 and 7): one option
# per purpose, each taking pass:, env:, file:, fd: and stdin; an
# unprefixed value is rejected; pass: on argv warns; a missing source for
# a needed purpose is a JSON error naming the option and nothing waits
# for input; with --interactive the prompt goes to stderr and stdout stays
# valid JSON; the typed codes missing_password, password_rejected,
# not_confirmed, invalid_key_type and invalid_key_size; xca --password
# without a prefix warns.

include("${LIB}")

# --- missing source: error naming the option, no database file -------
bxc("no password" 1 init --db "${DB}" --cn "No Pw")
expect_error("no password" missing_password)
if(NOT detail MATCHES "option --password")
  fail("missing_password must name --password: ${detail}")
endif()
if(EXISTS "${DB}")
  fail("a command without password created the database")
endif()

bxc("create" 0 init --db "${DB}" ${PW} --cn "Secret Root")

# existing database, a key operation without password
bxc("key without password" 1 request-cert --db "${DB}" --cn nopw)
expect_error("key without password" missing_password)
if(NOT detail MATCHES "option --password" OR NOT detail MATCHES "key 'nopw'")
  fail("missing_password must name option and object: ${detail}")
endif()
bxc("env not set" 1 list --db "${DB}" --password env:BXC_UNSET_VARIABLE)
expect_error("env not set" missing_password)
if(NOT detail MATCHES "BXC_UNSET_VARIABLE" OR NOT detail MATCHES "--password")
  fail("unreadable source: ${detail}")
endif()
bxc("wrong password" 1 list --db "${DB}" --password pass:wrong-one)
expect_error("wrong password" password_rejected)

# --- each source for --password -----------------------------------------
file(WRITE "${WORK}/pw.txt" "${DB_PW}\n")
set(i 0)
foreach(src "pass:${DB_PW}" env:BXC_DB_PW "file:${WORK}/pw.txt")
  math(EXPR i "${i} + 1")
  bxc("--password ${src}" 0 request-cert --db "${DB}" --password "${src}"
      --cn "pw-source-${i}")
  one_doc("--password ${src}" "${out}" cli-result r)
endforeach()
foreach(src fd:0 stdin)
  execute_process(COMMAND "${BXC_PKI}" request-cert --db "${DB}"
      --password ${src} --cn "pw-${src}"
    INPUT_FILE "${WORK}/pw.txt" WORKING_DIRECTORY "${WORK}"
    RESULT_VARIABLE r OUTPUT_VARIABLE o ERROR_VARIABLE e TIMEOUT ${T60})
  file(APPEND "${TRANSCRIPT}" "### --password ${src}\nexit ${r}\n${o}${e}\n")
  if(NOT r EQUAL 0)
    fail("--password ${src}: ${r} ${e}")
  endif()
  one_doc("--password ${src}" "${o}" cli-result x)
endforeach()

# pass: on argv warns on stderr, stdout stays JSON (a command that warns)
bxc("pass warning" 0 list --db "${DB}" --password "pass:${DB_PW}")
one_doc("pass warning" "${out}" list x)
if(NOT err MATCHES "Warning: --password pass:")
  fail("pass: on the command line must warn: ${err}")
endif()

# --- unprefixed or misspelt sources are rejected, never used ----------
foreach(o password sqlpass import-pass export-pass)
  foreach(v "${DB_PW}" "evn:BXC_DB_PW" "file:" "fd:x")
    bxc("--${o} ${v}" 2 list --db "${DB}" --${o} "${v}")
    expect_error("--${o} ${v}" invalid_secret_source)
    if(NOT detail MATCHES "--${o}")
      fail("invalid_secret_source must name --${o}: ${detail}")
    endif()
  endforeach()
endforeach()
foreach(o pin so-pin new-pin new-so-pin)
  bxc("--${o}" 2 list --db "${DB}" --${o} env:X)
  expect_error("--${o}" not_supported)
endforeach()

# --- --sqlpass, --import-pass and --export-pass accept every source ------
set(ENV{BXC_OTHER} "other-secret")
file(WRITE "${WORK}/other.txt" "other-secret\n")
foreach(o sqlpass import-pass export-pass)
  foreach(src "pass:other-secret" env:BXC_OTHER "file:${WORK}/other.txt")
    bxc("--${o} ${src}" 0 list --db "${DB}" ${PW} --${o} "${src}")
    one_doc("--${o} ${src}" "${out}" list x)
  endforeach()
  foreach(src fd:0 stdin)
    execute_process(COMMAND "${BXC_PKI}" list --db "${DB}" ${PW}
        --${o} ${src}
      INPUT_FILE "${WORK}/other.txt" WORKING_DIRECTORY "${WORK}"
      RESULT_VARIABLE r OUTPUT_VARIABLE o2 ERROR_VARIABLE e TIMEOUT ${T60})
    if(NOT r EQUAL 0)
      fail("--${o} ${src}: ${r} ${e}")
    endif()
  endforeach()
endforeach()
# a needed --sqlpass source that cannot be read names its option
bxc("sqlpass unreadable" 1 list --db "${DB}" ${PW} --sqlpass env:BXC_UNSET_VARIABLE)
expect_error("sqlpass unreadable" missing_password)
if(NOT detail MATCHES "--sqlpass")
  fail("missing --sqlpass source: ${detail}")
endif()

# --import-pass decrypts a key file: every source, missing, wrong
openssl_run(x genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256
    -out "${WORK}/k.pem")
openssl_run(x pkcs8 -topk8 -v2 aes-256-cbc -in k.pem -out enc.pem
    -passout pass:other-secret)
foreach(src "pass:other-secret" env:BXC_OTHER "file:${WORK}/other.txt")
  bxc("import ${src}" 0 show --file enc.pem --import-pass "${src}")
  one_doc("import ${src}" "${out}" key k)
endforeach()
foreach(src fd:0 stdin)
  execute_process(COMMAND "${BXC_PKI}" show --file enc.pem --import-pass ${src}
    INPUT_FILE "${WORK}/other.txt" WORKING_DIRECTORY "${WORK}"
    RESULT_VARIABLE r OUTPUT_VARIABLE o ERROR_VARIABLE e TIMEOUT ${T60})
  if(NOT r EQUAL 0)
    fail("--import-pass ${src}: ${r} ${e}")
  endif()
  one_doc("--import-pass ${src}" "${o}" key k)
endforeach()
bxc("import missing" 1 show --file enc.pem)
expect_error("import missing" missing_password)
if(NOT detail MATCHES "option --import-pass")
  fail("missing --import-pass: ${detail}")
endif()
bxc("import wrong" 1 show --file enc.pem --import-pass pass:nope)
expect_error("import wrong" password_rejected)

# --- --interactive without a terminal: a typed password error (BTD-145) --
# stdin is /dev/null (bxc()), the existing database needs its password
bxc("interactive without tty" 1 list --db "${DB}" --interactive)
expect_error("interactive without tty" missing_password)
if(NOT detail MATCHES "option --password")
  fail("--interactive without terminal must name --password: ${detail}")
endif()
# a new database needs a new password, also a key operation
bxc("interactive without tty, new db" 1 init --db "${WORK}/tty-new.xdb"
    --interactive --cn "No Tty")
expect_error("interactive without tty, new db" missing_password)
bxc("interactive without tty, key" 1 request-cert --db "${DB}"
    --interactive --cn no-tty)
expect_error("interactive without tty, key" missing_password)

# --- --interactive: prompt on stderr (the terminal), stdout JSON -----------
if(SCRIPT AND EXISTS "${SCRIPT}")
  # the answer comes after the prompt, which goes to interactive.err: the
  # prompt flushes earlier terminal input (tty_feed, BTD-230)
  file(REMOVE "${WORK}/interactive.err")
  tty_feed(feed "${WORK}/interactive.err" "${DB_PW}")
  execute_process(COMMAND sh -c
      "(${feed}) | '${SCRIPT}' -qec \"'${BXC_PKI}' list --db '${DB}' --interactive > '${WORK}/interactive.json' 2> '${WORK}/interactive.err'\" /dev/null"
    WORKING_DIRECTORY "${WORK}"
    RESULT_VARIABLE r OUTPUT_VARIABLE o ERROR_VARIABLE e TIMEOUT ${T60})
  file(READ "${WORK}/interactive.json" ij)
  file(READ "${WORK}/interactive.err" ie)
  file(APPEND "${TRANSCRIPT}" "### interactive\nexit ${r}\n--- stdout\n${ij}--- stderr\n${ie}\n--- tty\n${o}${e}\n")
  # stderr is a file here: without a terminal on stdin and stderr the
  # prompt must still not reach stdout
  if(NOT r EQUAL 0)
    fail("--interactive: exit ${r}: ${ie} ${o}")
  endif()
  one_doc("--interactive" "${ij}" list x)
  if(NOT ie MATCHES "Password")
    fail("--interactive: the prompt is not on stderr: '${ie}'")
  endif()
else()
  message(STATUS "script(1) missing: --interactive not tested")
endif()

# --- typed error codes ---------------------------------------------------
# --key takes exactly the names of the bootstrap keyType: anything else,
# also the xca syntax, is invalid_key_type; the name fixes size and curve
foreach(kt foo rsa:2048 RSA-2048 rsa-1024 ec-p224 ec:prime256v1 ed25519:256
    dsa-2048 ml-dsa-65:2048)
  bxc("invalid key type '${kt}'" 1 request-cert --db "${DB}" ${PW} --cn kt
      --key "${kt}")
  expect_error("invalid key type '${kt}'" invalid_key_type)
endforeach()
# a size reaches the service only through xca --keygen (below)
xca_run("xca invalid key type" 1 --database "${DB}" ${PW} --json
    --keygen FOO:1)
expect_error("xca invalid key type" invalid_key_type)
xca_run("xca invalid curve" 1 --database "${DB}" ${PW} --json
    --keygen EC:nocurve --name nocurve)
expect_error("xca invalid curve" invalid_curve)
foreach(kt ED25519:256 ED448:456 ML-DSA-65:2048 RSA:abc RSA:16)
  xca_run("xca invalid size ${kt}" 1 --database "${DB}" ${PW} --json
      --keygen ${kt} --name "xca-${kt}")
  expect_error("xca invalid size ${kt}" invalid_key_size)
endforeach()
xca_run("xca not confirmed" 1 --database "${DB}" ${PW} --json
    --keygen RSA:768 --name small)
expect_error("xca not confirmed" not_confirmed)

# the rejected key generations are audited (after the rollback)
audit_entries(lines)
split_lines("${lines}" all)
set(fails "")
foreach(l IN LISTS all)
  if(l MATCHES "\"error_code\":\"invalid_key_size\"")
    list(APPEND fails "${l}")
  endif()
endforeach()
list(LENGTH fails n)
if(NOT n EQUAL 5)
  fail("expected 5 key.generate failures invalid_key_size, got ${n}:\n${fails}")
endif()
foreach(f IN LISTS fails)
  string(JSON a GET "${f}" action)
  string(JSON ch GET "${f}" channel)
  if(NOT a STREQUAL "key.generate" OR NOT ch STREQUAL "cli")
    fail("failure entry: ${f}")
  endif()
endforeach()

# --- xca: unprefixed --password still works, with a warning --------------
xca_run("xca unprefixed" 0 --database "${DB}" --password "${DB_PW}"
    --list-items)
if(NOT err MATCHES "Warning: --password without a source prefix")
  fail("xca --password without prefix must warn: ${err}")
endif()
if(out MATCHES "Warning")
  fail("the warning must not reach stdout: ${out}")
endif()
message(STATUS "bxc-pki secrets ok")
