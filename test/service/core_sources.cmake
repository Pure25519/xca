# The sources of xcacore name no GUI code (BTD-36): no include of widgets/
# or of a generated ui_*.h, no Qt Gui or Widgets class, no qApp. Comments
# count too, so that the file list stays easy to grep.
# cmake -DSOURCES=<a|b|...> -P core_sources.cmake

set(gui_classes
  QDialog QMessageBox QWidget QApplication QGuiApplication qApp QCursor
  QPixmap QIcon QImage QMenu QAction QHeaderView QBrush QPalette QColor
  QFont QInputDialog QFileDialog QProgressBar QValidator QTextEdit
  QClipboard QDesktopServices QTreeView)
list(JOIN gui_classes "|" classes)
set(word "(^|[^A-Za-z0-9_])(${classes})([^A-Za-z0-9_]|$)")

string(REPLACE "|" ";" SOURCES "${SOURCES}")
set(hits "")
set(count 0)
foreach(src IN LISTS SOURCES)
  if(NOT src MATCHES "\\.(cpp|h)$")
    continue()
  endif()
  math(EXPR count "${count} + 1")
  file(STRINGS "${src}" lines)
  foreach(line IN LISTS lines)
    if(line MATCHES "widgets/" OR line MATCHES "ui_[A-Za-z0-9_]+\\.h"
        OR line MATCHES "${word}")
      string(APPEND hits "\n${src}: ${line}")
    endif()
  endforeach()
endforeach()
if(count LESS 50)
  message(FATAL_ERROR "only ${count} sources given: the check is broken")
endif()
if(hits)
  message(FATAL_ERROR "GUI references in the core sources:${hits}")
endif()
message(STATUS "${count} core sources without GUI references")
