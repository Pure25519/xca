# xca --no-gui --migrate-template (BTD-167): an imported XCA template
# becomes a generic profile in the profile store, audited as
# profile.migrate; the template stays; a second migration of the same
# name and an unknown template fail with exit code 1.
# cmake -DXCA=<xca> -DSOURCE=<source dir> -DWORK=<scratch dir> -P cli_migrate_template.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

set(db --database "${WORK}/migrate.xdb" --password pass:migrate-test)
function(expect code label)
  execute_process(COMMAND "${XCA}" --no-gui ${db} ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out
    TIMEOUT 30)
  if(NOT rc EQUAL code)
    fail("${label}: expected exit code ${code}, got '${rc}':\n${out}")
  endif()
  set(out "${out}" PARENT_SCOPE)
endfunction()

expect(0 "import template" --import "${SOURCE}/misc/TLS_server.xca")
expect(0 "migrate" --migrate-template TLS_server)
if(NOT out MATCHES "xca-tls-server.*version 1")
  fail("migrate: profile and version missing:\n${out}")
endif()
expect(0 "migrate with a name" --migrate-template TLS_server --name web-legacy)
if(NOT out MATCHES "web-legacy.*version 1")
  fail("migrate with a name: profile missing:\n${out}")
endif()
expect(1 "migrate twice" --migrate-template TLS_server)
if(NOT out MATCHES "document_exists|exists already")
  fail("migrate twice: no error naming the existing profile:\n${out}")
endif()
expect(1 "unknown template" --migrate-template no-such-template)
if(NOT out MATCHES "no-such-template")
  fail("unknown template: no error naming it:\n${out}")
endif()
# the template stays, the audit log has the migrations
expect(0 "template stays" --list-items)
if(NOT out MATCHES "TLS_server")
  fail("the template is gone:\n${out}")
endif()
expect(0 "audit export" --audit-export "${WORK}/audit.jsonl")
file(READ "${WORK}/audit.jsonl" audit)
string(REGEX MATCHALL "\"profile.migrate\"[^\n]*\"success\"" ok "${audit}")
list(LENGTH ok n)
if(NOT n EQUAL 2)
  fail("expected two successful profile.migrate entries, got ${n}:\n${audit}")
endif()
file(REMOVE_RECURSE "${WORK}")
