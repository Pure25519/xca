/* vi: set sw=4 ts=4:
 *
 * A SoftHSM v2 token for the token tests (BTD-126), see SoftHsmToken.h
 */

#include <QDir>
#include <QFile>
#include <QMutex>
#include <QRandomGenerator>
#include <QSet>

#include "lib/exception.h"
#include "lib/pkcs11.h"
#include "lib/pk11_attribute.h"

#include "SoftHsmToken.h"

const char SoftHsmToken::label[] = "bxc-pki test token";
const char SoftHsmToken::pinSource[] = "env:BXC_PKI_TEST_TOKEN_PIN";
const char SoftHsmToken::soPinSource[] = "env:BXC_PKI_TEST_TOKEN_SO_PIN";
const char SoftHsmToken::wrongPinSource[] =
	"env:BXC_PKI_TEST_TOKEN_WRONG_PIN";

/* 16 random hex digits, new for every run */
static QByteArray randomPin()
{
	quint64 v = QRandomGenerator::system()->generate64();
	return QByteArray::number(v, 16).rightJustified(16, '0');
}

QString SoftHsmToken::setUp()
{
	module = qEnvironmentVariable("SOFTHSM2_MODULE");
	if (module.isEmpty())
		return "SOFTHSM2_MODULE is not set: no PKCS#11 module to test "
			"with (the bxc-pki build image has SoftHSM, BTD-126)";
	if (!QFile::exists(module))
		return QString("the PKCS#11 module %1 (SOFTHSM2_MODULE) does "
			"not exist").arg(module);
	if (!dir.isValid() || !QDir(dir.path()).mkdir("tokens"))
		return "no temporary directory for the token";

	QString conf = dir.filePath("softhsm2.conf");
	QFile f(conf);
	if (!f.open(QIODevice::WriteOnly))
		return "the SoftHSM configuration cannot be written";
	f.write(QString("directories.tokendir = %1\n"
		"objectstore.backend = file\nlog.level = ERROR\n")
		.arg(dir.filePath("tokens")).toUtf8());
	f.close();
	qputenv("SOFTHSM2_CONF", QFile::encodeName(conf));

	pin = randomPin();
	soPin = randomPin();
	QByteArray wrong = randomPin();
	qputenv("BXC_PKI_TEST_TOKEN_PIN", pin);
	qputenv("BXC_PKI_TEST_TOKEN_SO_PIN", soPin);
	qputenv("BXC_PKI_TEST_TOKEN_WRONG_PIN", wrong);

	QString reason;
	try {
		if (!load())
			throw errorEx(QString("the PKCS#11 module %1 does not "
				"load").arg(module));
		slotidList all = pkcs11::getSlotList();
		if (all.isEmpty())
			throw errorEx("the PKCS#11 module has no slot");
		{
			pkcs11 p11;
			p11.initToken(all[0], (unsigned char *)soPin.data(),
				soPin.size(), label);
		}
		/* SoftHSM gives an initialised token a new slot id */
		PasswordSourceScope so(pass_info::TokenSoPin, soPinSource);
		PasswordSourceScope user(pass_info::NewTokenPin, pinSource);
		pkcs11 p11;
		p11.initPin(slot());
	} catch (errorEx &err) {
		reason = "the SoftHSM token cannot be set up: " +
			err.getString();
	}
	pkcs11::libraries.remove_libs();
	return reason;
}

bool SoftHsmToken::load() const
{
	pkcs11::libraries.load(module);
	return pkcs11::libraries.loaded();
}

slotid SoftHsmToken::slot() const
{
	pkcs11 p11;
	for (const slotid &s : pkcs11::getSlotList()) {
		if (p11.tokenInfo(s).label().trimmed() == label)
			return s;
	}
	throw errorEx("the SoftHSM test token is not in the slot list");
}

QStringList SoftHsmToken::labels(unsigned long cls) const
{
	TokenPinScope scope;
	pkcs11 p11;
	QStringList l;

	p11.startSession(slot());
	p11.tokenLogin(label, false);
	pk11_attlist atts(pk11_attr_ulong(CKA_CLASS, cls));
	for (CK_OBJECT_HANDLE h : p11.objectList(atts)) {
		pk11_attr_data name(CKA_LABEL);
		p11.loadAttribute(name, h);
		l << name.getText();
	}
	p11.logout();
	l.sort();
	return l;
}

QString SoftHsmToken::oneLibcrypto()
{
#if defined(Q_OS_LINUX)
	QFile maps("/proc/self/maps");
	if (!maps.open(QIODevice::ReadOnly))
		return "/proc/self/maps cannot be read";
	QSet<QString> libs;
	for (const QByteArray &line : maps.readAll().split('\n')) {
		int at = line.indexOf('/');
		if (at >= 0 && line.contains("libcrypto"))
			libs << QString::fromLocal8Bit(line.mid(at));
	}
	if (libs.size() == 1 && libs.begin()->contains("libcrypto.so.4"))
		return QString();
	QStringList all = libs.values();
	all.sort();
	return all.isEmpty() ? "no libcrypto mapped" : all.join(", ");
#else
	return QString();
#endif
}

static QMutex messageLock;
static QStringList messages;
static QtMessageHandler previousHandler;

static void recordMessage(QtMsgType type, const QMessageLogContext &ctx,
			  const QString &msg)
{
	{
		QMutexLocker lock(&messageLock);
		messages << msg;
	}
	if (previousHandler)
		previousHandler(type, ctx, msg);
}

void SoftHsmToken::watchMessages()
{
	QtMessageHandler old = qInstallMessageHandler(recordMessage);
	if (old != recordMessage)
		previousHandler = old;
}

QStringList SoftHsmToken::messagesWithPin() const
{
	QMutexLocker lock(&messageLock);
	QStringList found;
	for (const QString &m : messages) {
		if (m.contains(QString::fromLatin1(pin)) ||
		    m.contains(QString::fromLatin1(soPin)))
			found << QString("a message (%1 characters) contains a "
				"PIN").arg(m.size());
	}
	return found;
}
