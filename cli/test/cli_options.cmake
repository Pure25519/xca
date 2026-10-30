# The shared option parser of bxc-pki (BTD-41, BTD-53 port plan): unknown
# options, missing or wrong values, repeated single options, conflicting
# options (--validity with --not-after) and unexpected arguments are JSON
# errors with exit code 2, never ignored; --help of every command; --plan
# writes nothing; --text output.

include("${LIB}")

# Every case runs before the database is opened: none is created
set(db --db "${DB}")
foreach(case
    "unknown_option|init;--cn;x;--colour;red"
    "unknown_option|list;--yes"
    "missing_value|init;--cn"
    "duplicate_option|init;--cn;a;--cn;b"
    "invalid_value|init;--cn;x;--path-len;abc"
    "invalid_value|init;--cn;x;--path-len;-1"
    "invalid_value|list;--text=yes"
    "conflicting_options|init;--cn;x;--validity;P1Y;--not-after;2030-01-01T00:00:00Z"
    "conflicting_options|init;--cn;x;--not-before;2030-01-01T00:00:00Z;--backdate;PT5M"
    "conflicting_options|init;--cn;x;--subject;CN=y"
    "conflicting_options|request-cert;--cn;x;--use-key;1;--key;rsa-2048"
    "conflicting_options|request-cert;--cn;x;--key-file;k.pem;--key;ec-p256"
    "conflicting_options|list;--plan"
    "missing_option|sign;r1"
    "missing_argument|sign;--ca;1"
    "unexpected_argument|init;extra;--cn;x"
    "unexpected_argument|sign;a;b;--ca;1"
    "not_supported|sign;r1;--ca;1;--profile;opcua-server"
    "not_supported|list;--pin;env:PIN"
    "unknown_command|frobnicate")
  string(REPLACE "|" ";" parts "${case}")
  list(GET parts 0 code)
  list(SUBLIST parts 1 -1 args)
  bxc("${code}: ${args}" 2 ${args} ${db})
  expect_error("${code}: ${args}" ${code})
endforeach()
if(EXISTS "${DB}")
  fail("a usage error created the database")
endif()

# --help of the tool and of each command go to stdout, exit 0
bxc("help" 0 help)
if(NOT out MATCHES "Commands:")
  fail("help: ${out}")
endif()
foreach(cmd init request-cert sign list show)
  bxc("${cmd} --help" 0 ${cmd} --help)
  if(NOT out MATCHES "bxc-pki ${cmd}")
    fail("${cmd} --help: ${out}")
  endif()
  bxc("help ${cmd}" 0 help ${cmd})
endforeach()

# --plan: cli_plan.cmake

# --text: the result for people on stdout, an error as text on stderr
bxc("text" 0 init ${db} ${PW} --cn "Text Root" --text)
if(NOT out MATCHES "^written key [0-9]+ 'Text Root'\nwritten certificate [0-9]+ 'Text Root' serial [0-9A-F]+ until ")
  fail("--text result: ${out}")
endif()
bxc("text error" 2 init ${db} ${PW} --text)
if(NOT out STREQUAL "" OR NOT err MATCHES "^Error: init needs --cn or --subject \\[missing_option\\]")
  fail("--text error: '${out}' '${err}'")
endif()
bxc("list text" 0 list ${db} ${PW} --text)
if(NOT out MATCHES "key +Text Root")
  fail("list --text: ${out}")
endif()
message(STATUS "bxc-pki options ok")
