# xcacore and the binaries that link it need no Qt Gui, Widgets or Help
# (BTD-36): readelf -d of each binary lists no such library. The GUI binary
# is the counter check: it must list Qt Widgets, or the check finds nothing.
# cmake -DREADELF=<readelf> -DBINARIES=<a|b|...> -DGUI_BINARY=<xca>
#       -P core_link.cmake

function(needed bin out)
  execute_process(COMMAND "${READELF}" -d "${bin}"
    OUTPUT_VARIABLE dyn RESULT_VARIABLE rc)
  if(NOT rc EQUAL 0)
    message(FATAL_ERROR "readelf -d ${bin} failed (${rc})")
  endif()
  set(${out} "${dyn}" PARENT_SCOPE)
endfunction()

needed("${GUI_BINARY}" gui)
if(NOT gui MATCHES "libQt[0-9]*Widgets")
  message(FATAL_ERROR "${GUI_BINARY} lists no Qt Widgets: the check is broken")
endif()

string(REPLACE "|" ";" BINARIES "${BINARIES}")
foreach(bin IN LISTS BINARIES)
  needed("${bin}" dyn)
  if(NOT dyn MATCHES "libQt[0-9]*Core")
    message(FATAL_ERROR "${bin} lists no Qt Core: the check is broken")
  endif()
  if(dyn MATCHES "libQt[0-9]*(Gui|Widgets|Help)[^ \n]*")
    message(FATAL_ERROR "${bin} needs ${CMAKE_MATCH_0}")
  endif()
  get_filename_component(name "${bin}" NAME)
  message(STATUS "${name}: no Qt Gui, Widgets or Help")
endforeach()
