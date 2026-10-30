/* vi: set sw=4 ts=4:
 *
 * The Options dialog stores only the options the user changed
 * (BTD-187): a stored setting is a choice, not the default the dialog
 * showed. The dialog is driven in the GUI thread (QTimer::singleShot).
 */

#include <QTest>
#include <QTimer>
#include <functional>
#include <QSqlQuery>

#include "lib/digest.h"
#include "lib/settings.h"
#include "widgets/MainWindow.h"
#include "ui_Options.h"
#include "ui_SearchPkcs11.h"
#include "widgets/Options.h"

#include "main.h"

static QMap<QString, QString> settingsRows()
{
	QMap<QString, QString> rows;
	QSqlQuery q("SELECT key_, value FROM settings");
	while (q.next())
		rows[q.value(0).toString()] = q.value(1).toString();
	return rows;
}

/* Runs the dialog; change() edits it in the GUI thread before OK */
static int runOptions(std::function<void(Options *)> change)
{
	Options *dlg = new Options(mainwin);
	QTimer::singleShot(0, dlg, [dlg, change]() {
		change(dlg);
		dlg->accept();
	});
	int r = dlg->exec();
	delete dlg;
	return r;
}

void test_main::optionsStoreChangedOnly()
{
	try {
		openDB();
		QMap<QString, QString> before = settingsRows();

		/* OK without a change stores nothing */
		QCOMPARE(runOptions([](Options *) {}), (int)QDialog::Accepted);
		QMap<QString, QString> after = settingsRows();
		QStringList added;
		for (const QString &k : after.keys())
			if (!before.contains(k) || before[k] != after[k])
				added << k + "=" + after[k];
		QVERIFY2(added.isEmpty(), CCHAR(added.join(", ")));

		/* one change stores exactly that one */
		QCOMPARE(runOptions([](Options *o) {
			o->suppress->setChecked(!o->suppress->isChecked());
		}), (int)QDialog::Accepted);
		QMap<QString, QString> changed = settingsRows();
		QStringList diff;
		for (const QString &k : changed.keys())
			if (!after.contains(k) || after[k] != changed[k])
				diff << k;
		QCOMPARE(diff, QStringList("suppress_messages"));
		QCOMPARE(changed["suppress_messages"], QString("yes"));

		/* and changing it back is stored too: no other option moves */
		QCOMPARE(runOptions([](Options *o) {
			o->suppress->setChecked(false);
			o->serial_len->setValue(o->serial_len->value() + 8);
		}), (int)QDialog::Accepted);
		QMap<QString, QString> back = settingsRows();
		diff.clear();
		for (const QString &k : back.keys())
			if (!changed.contains(k) || changed[k] != back[k])
				diff << k;
		diff.sort();
		QCOMPARE(diff, QStringList({ "serial_len", "suppress_messages" }));
		QCOMPARE(back["suppress_messages"], QString("no"));

		/* back to the default hash after another one was chosen: the
		 * old check against the default did not store it (BTD-52) */
		Settings["default_hash"] = digest(NID_sha384).name();
		QCOMPARE(runOptions([](Options *o) {
			o->hashAlgo->setCurrent(digest(NID_sha256));
		}), (int)QDialog::Accepted);
		QCOMPARE(settingsRows()["default_hash"],
			digest(NID_sha256).name());
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
