/* vi: set sw=4 ts=4:
 *
 * The hex option of the password dialog follows the purpose of the
 * secret, not its translated type text (BTD-73). PwDialog compared
 * getType(), which is tr("PIN"), with "PIN": in French ("NIP") the hex
 * option was hidden for every PIN.
 */

#include <QApplication>
#include <QTranslator>

#include "ui_PwDialog.h"
#include "widgets/PwDialog.h"
#include "lib/pass_info.h"

#include "main.h"

namespace {
/* The PIN and password texts of lang/xca_fr.ts, nothing else */
class FrenchPassInfo: public QTranslator
{
  public:
	QString translate(const char *context, const char *source,
		const char *, int) const override
	{
		if (QLatin1String(context) != "pass_info")
			return QString();
		if (QLatin1String(source) == "PIN")
			return QString("NIP");
		if (QLatin1String(source) == "Password")
			return QString("Mot de passe");
		return QString();
	}
	bool isEmpty() const override
	{
		return false;
	}
};

void checkHexOption(const char *language)
{
	pass_info key("Password", "key password");
	PwDialog keyDialog(&key);
	QVERIFY2(keyDialog.takeHex->isHidden(), language);

	pass_info pin("PIN", "token PIN");
	pin.setPin();
	PwDialog pinDialog(&pin);
	QVERIFY2(!pinDialog.takeHex->isHidden(), language);

	pass_info soPin("SO PIN", "token SO PIN");
	soPin.setPin(true);
	PwDialog soPinDialog(&soPin);
	QVERIFY2(!soPinDialog.takeHex->isHidden(), language);

	pass_info newPin("New PIN", "new token PIN");
	newPin.setPin();
	newPin.setPurpose(pass_info::NewTokenPin);
	PwDialog newPinDialog(&newPin);
	QVERIFY2(!newPinDialog.takeHex->isHidden(), language);
}
}

void test_main::pinHexOption()
{
	checkHexOption("English");
	if (QTest::currentTestFailed())
		return;

	FrenchPassInfo french;
	QVERIFY(qApp->installTranslator(&french));
	pass_info probe("t", "d");
	probe.setPin();
	QCOMPARE(probe.getType(), QString("NIP"));
	checkHexOption("French");
	qApp->removeTranslator(&french);
}
