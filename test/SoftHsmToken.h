/* vi: set sw=4 ts=4:
 *
 * A SoftHSM v2 token for the token tests (BTD-126), shared by the service
 * tests and testxca. The module comes from SOFTHSM2_MODULE (the bxc-pki
 * build image builds it against OpenSSL 4.1, /opt/softhsm); without it the
 * tests skip with the reason setUp() returns.
 *
 * setUp() makes one token per run in a temporary directory (SOFTHSM2_CONF
 * points there) with a random PIN and SO-PIN. The PINs only reach XCA
 * through the password sources env:BXC_PKI_TEST_TOKEN_PIN and
 * env:BXC_PKI_TEST_TOKEN_SO_PIN, never as a literal and never in a message;
 * watchMessages() records every Qt message so that a test can check that
 * none of them shows a PIN.
 */

#ifndef __SOFTHSMTOKEN_H
#define __SOFTHSMTOKEN_H

#include <QStringList>
#include <QTemporaryDir>

#include "lib/PwDialogCore.h"
#include "lib/pkcs11_lib.h"

class SoftHsmToken
{
	QTemporaryDir dir{};
	QString module{};
	QByteArray pin{}, soPin{};

  public:
	static const char label[];
	static const char pinSource[];
	static const char soPinSource[];
	static const char wrongPinSource[];

	/* Empty when the token is ready, else the reason; see
	 * SOFTHSM_SET_UP() */
	QString setUp();
	/* SOFTHSM2_MODULE is set: a test must run with the token, a
	 * setup error is a broken fixture (BTD-298) */
	bool configured() const
	{
		return !module.isEmpty();
	}
	/* Loads the module into XCA (pkcs11::libraries); a database close
	 * unloads it again (remove_libs) */
	bool load() const;
	/* The slot of the token of setUp() */
	slotid slot() const;
	/* The labels of the objects of class cls (CKO_*) on the token, read
	 * after a login with the PIN */
	QStringList labels(unsigned long cls) const;
	/* Empty when the process maps exactly one libcrypto and it is
	 * libcrypto.so.4 (/proc/self/maps; rule one-libcrypto, BTD-251),
	 * else the libraries found */
	static QString oneLibcrypto();

	/* Records every Qt message until messagesWithPin() */
	static void watchMessages();
	/* The recorded messages that contain a PIN of the token */
	QStringList messagesWithPin() const;
	/* The value of the PIN, only to compare it with what a test reads
	 * back (audit table, files); never printed */
	QByteArray pinValue() const
	{
		return pin;
	}
	QByteArray soPinValue() const
	{
		return soPin;
	}
};

/* Sets up token in a test function: without SOFTHSM2_MODULE the test
 * skips with the reason; with it a setup error fails the test, so that a
 * broken fixture does not silently stop the token tests (BTD-298) */
#define SOFTHSM_SET_UP(token) do { 	QString softHsmWhy_ = (token).setUp(); 	if (!softHsmWhy_.isEmpty()) { 		if ((token).configured()) 			QFAIL(qPrintable(softHsmWhy_)); 		QSKIP(qPrintable(softHsmWhy_)); 	} } while (0)

/* SoftHSM always offers one free slot next to the token of setUp(), so
 * a path that lets the user choose the token asks; this answers with the
 * test token and passes everything else to the headless dialog */
class TokenChooser : public PwDialogHeadless
{
  public:
	int selectToken(const QStringList &names) override
	{
		for (int i = 0; i < names.size(); i++) {
			if (names[i].startsWith(SoftHsmToken::label))
				return i;
		}
		return -1;
	}
};

/* The token PIN from its source for the life of the scope */
class TokenPinScope
{
	PasswordSourceScope pin;

  public:
	explicit TokenPinScope(const char *source = SoftHsmToken::pinSource)
		: pin(pass_info::TokenPin, source)
	{
	}
};

#endif
