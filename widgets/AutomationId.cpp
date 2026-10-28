/* vi: set sw=4 ts=4:
 *
 * Stable automation IDs (objectName) for GUI test bots.
 * Naming scheme: doc/automation-ids.md
 */

#include "AutomationId.h"

#include <QApplication>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QMetaEnum>
#include <QPushButton>
#include <QRegularExpression>

QString AutomationId::sanitize(const QString &s)
{
	QString r = s;
	return r.replace(QRegularExpression("[^A-Za-z0-9_]"), "_");
}

void AutomationId::nameButtons(QWidget *w)
{
	QMetaEnum me = QMetaEnum::fromType<QDialogButtonBox::StandardButtons>();

	foreach(QDialogButtonBox *box, w->findChildren<QDialogButtonBox*>()) {
		foreach(QAbstractButton *b, box->buttons()) {
			if (!b->objectName().isEmpty())
				continue;
			QDialogButtonBox::StandardButton sb = box->standardButton(b);
			const char *key = me.valueToKey(sb);
			if (sb == QDialogButtonBox::NoButton || !key)
				continue;
			QString name(key);
			name[0] = name[0].toLower();
			b->setObjectName("btn_" + name);
		}
	}
}

namespace {
class ShowFilter : public QObject
{
  public:
	ShowFilter(QObject *parent) : QObject(parent) { }
	bool eventFilter(QObject *watched, QEvent *ev) override
	{
		if (ev->type() == QEvent::Show) {
			QDialog *dlg = qobject_cast<QDialog*>(watched);
			if (dlg)
				AutomationId::nameButtons(dlg);
		}
		return false;
	}
};
}

void AutomationId::install()
{
	static ShowFilter *filter;

	if (!filter && qApp) {
		filter = new ShowFilter(qApp);
		qApp->installEventFilter(filter);
	}
}
