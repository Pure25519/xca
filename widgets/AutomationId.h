/* vi: set sw=4 ts=4:
 *
 * Stable automation IDs (objectName) for GUI test bots.
 * Naming scheme: doc/automation-ids.md
 */

#ifndef __AUTOMATIONID_H
#define __AUTOMATIONID_H

#include <QAction>
#include <QMenu>
#include <QObject>
#include <QString>
#include <type_traits>

class QWidget;

/* Sets the objectName and returns the object, so it can be chained:
 * setAutomationId(menu->addAction(...), "act_file_open")->setShortcut(..)
 * A menu's menuAction() gets the same name: the accessibility tree shows
 * a submenu entry as that action. */
template <class T> T *setAutomationId(T *obj, const QString &id)
{
	obj->setObjectName(id);
	if constexpr (std::is_base_of_v<QMenu, T>)
		obj->menuAction()->setObjectName(id);
	return obj;
}

namespace AutomationId
{
	/* Characters outside [A-Za-z0-9_] become '_' */
	QString sanitize(const QString &s);

	/* Names the unnamed standard buttons of every QDialogButtonBox
	 * below w "btn_<button>", e.g. btn_ok, btn_cancel, btn_yesToAll */
	void nameButtons(QWidget *w);

	/* Calls nameButtons() for every dialog and message box when it is
	 * shown. Installed once on the application object. */
	void install();
}

#endif
