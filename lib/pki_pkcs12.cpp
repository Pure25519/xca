/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_pkcs12.h"
#include "pki_evp.h"
#include "pki_x509.h"

#include "pass_info.h"
#include "exception.h"
#include "func.h"
#include "PwDialogCore.h"
#include "settings.h"
#include "XcaWarningCore.h"

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/stack.h>

#include <memory>

pki_pkcs12::pki_pkcs12(const QString &d, pki_x509 *acert, pki_key *akey)
	:pki_multi(d), cert(acert), key(akey)
{
	append_item(key);
	append_item(cert);
}

pki_pkcs12::pki_pkcs12(const QString &fname)
	:pki_multi(fname)
{
	XFile file(fname);
	file.open_read();
	parse(file.readAll(), fname);
}

pki_pkcs12::pki_pkcs12(const QByteArray &ba, const QString &name)
	:pki_multi(name)
{
	parse(ba, name);
}

void pki_pkcs12::parse(const QByteArray &ba, const QString &fname)
{
	Passwd pass;
	EVP_PKEY *mykey = NULL;
	X509 *mycert = NULL;
	pass_info p(XCA_TITLE, tr("Please enter the password to decrypt the PKCS#12 file:\n%1").arg(compressFilename(fname)));
	p.setPurpose(pass_info::ImportPassword);
	const X509_ALGOR *macalgid = NULL;
	const ASN1_INTEGER *maciter = NULL;
	const ASN1_OBJECT *macobj = NULL;

	setFilename(fname);
	BioByteArray b(ba);

	PKCS12 *pkcs12 = d2i_PKCS12_bio(b.ro(), NULL);
	if (pki_ign_openssl_error()) {
		if (pkcs12)
			PKCS12_free(pkcs12);
		throw errorEx(tr("Unable to load the PKCS#12 (pfx) file %1.")
				.arg(fname));
	}
	PKCS12_get0_mac(NULL, &macalgid, NULL, &maciter, pkcs12);
	if (macalgid)
		X509_ALGOR_get0(&macobj, NULL, NULL, macalgid);
	if (macobj) {
		algorithm = OBJ_obj2QString(macobj);
		if (maciter)
			algorithm += QString(", iteration %1").arg(a1int(maciter).toDec());
	}
	while (!PKCS12_verify_mac(pkcs12, pass.constData(), pass.size())) {
		if (pass.size() > 0)
			XCA_PASSWD_ERROR();
		enum open_result result = PwDialogCore::execute(&p, &pass);
		if (result != pw_ok) {
			/* cancel pressed */
			PKCS12_free(pkcs12);
			failed_files << fname;
			throw result;
		}
	}
	STACK_OF(X509) *certstack = sk_X509_new_null();
	PKCS12_parse(pkcs12, pass.constData(), &mykey, &mycert, &certstack);
	int error = ERR_peek_error();
	if (ERR_GET_REASON(error) == PKCS12_R_MAC_VERIFY_FAILURE) {
		pki_ign_openssl_error();
		PKCS12_free(pkcs12);
		sk_X509_free(certstack);
		failed_files << fname;

		throw errorEx(getClassName(),
			 tr("The supplied password was wrong (%1)")
				.arg(ERR_reason_error_string(error)));
	}
	pki_ign_openssl_error();
	if (mycert) {
		const unsigned char *str = X509_alias_get0(mycert, NULL);
		if (str)
			alias = QString::fromUtf8((const char *)str);
		alias = QString::fromUtf8(alias.toLatin1());
		cert = new pki_x509(mycert);
		Q_CHECK_PTR(cert);
		if (alias.isEmpty()) {
			cert->autoIntName(fname);
			alias = cert->getIntName();
		} else {
			cert->setIntName(alias);
		}
		cert->pkiSource = imported;
		inheritFilename(cert);
		append_item(cert);
	}
	if (mykey) {
		key = new pki_evp(mykey);
		/* the file's own protection for JSON (BTD-41) */
		key->setFileEncrypted(pass.size() > 0);
		key->setIntName(alias + "_key");
		key->pkiSource = imported;
		inheritFilename(key);
		append_item(key);
	}
	for (int i = 0; i < sk_X509_num(certstack); ++i) {
		X509 *crt = sk_X509_value(certstack, i);
		if (!crt)
			continue;
		pki_x509 *cacert = new pki_x509(crt);
		Q_CHECK_PTR(cacert);
		if (alias.isEmpty()) {
			cacert->autoIntName(QString());
		} else {
			cacert->setIntName(QString(alias + "_ca_%1").arg(i));
		}
		cacert->pkiSource = imported;
		inheritFilename(cacert);
		append_item(cacert);
	}
	sk_X509_free(certstack);
	PKCS12_free(pkcs12);
	pki_openssl_error();
}

void pki_pkcs12::writePKCS12(QIODevice &file, encAlgo &encAlgo,
			const Passwd &pass) const
{
	if (cert == NULL || key == NULL)
		my_error(tr("No key or no Cert and no pkcs12"));

	/* Freed on every path, also when a step throws: the decrypted key
	 * must not stay in memory (BTD-194). First the key:
	 * decryptKeyForExport() may throw (BTD-16) */
	pki_evp *evp = dynamic_cast<pki_evp *>(key);
	std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
		evp ? evp->decryptKeyForExport() : key->decryptKey(),
		&EVP_PKEY_free);

	/* sk_X509_free(): the certificates belong to the pki_x509 items */
	std::unique_ptr<STACK_OF(X509), void (*)(STACK_OF(X509) *)>
		certstack(sk_X509_new_null(),
			[](STACK_OF(X509) *sk) { sk_X509_free(sk); });
	Q_CHECK_PTR(certstack.get());
	foreach(pki_base *pki, multi) {
		pki_x509 *x = dynamic_cast<pki_x509*>(pki);
		if (x && x != cert)
			sk_X509_push(certstack.get(), x->getCert());
	}
	int certAlgoNid, keyAlgoNid;
	certAlgoNid = keyAlgoNid = encAlgo.getEncAlgoNid();

	// The very ancient 40BitRC2_CBC algorithm at least can
	// be combined with TripleDES_CBC for the keys.
	if (keyAlgoNid == NID_pbe_WithSHA1And40BitRC2_CBC)
		keyAlgoNid = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;

	for (const QString &line : key->getComment().split('\n')) {
		QStringList kv = line.split(":");
		qDebug() << line << kv;
		if (kv.size() != 2 || kv[0] != "CSP")
			continue;
		QByteArray csp = kv[1].trimmed().toLatin1();
		EVP_PKEY_add1_attr_by_NID(pkey.get(), NID_ms_csp_name,
			MBSTRING_ASC, (const unsigned char*)csp.constData(), csp.size());
	}

	std::unique_ptr<PKCS12, decltype(&PKCS12_free)> pkcs12(
		PKCS12_create(pass.constData(), getIntName().toUtf8().data(),
				pkey.get(), cert->getCert(), certstack.get(),
				keyAlgoNid, certAlgoNid, 0, 0, 0),
		&PKCS12_free);
	pkey.reset();
	/* e.g. a key that does not belong to the certificate; before,
	 * Q_CHECK_PTR() reported it as std::bad_alloc (BTD-194) */
	if (!pkcs12)
		throw errorEx(tr("The PKCS#12 file '%1' cannot be created: %2")
				.arg(getIntName(), take_openssl_errors()));
	pki_openssl_error();

	/* The MAC set explicitly, not left to OpenSSL's default: SHA-1 for
	 * legacy readers only, else HMAC-SHA256 (BTD-52). Not PBMAC1
	 * (RFC 9579): Windows, Java and OpenSSL before 3.4 cannot check it */
	if (encAlgo.legacy())
		PKCS12_set_mac(pkcs12.get(), pass.constData(), -1, NULL, 0, 1,
				EVP_sha1());
	else
		PKCS12_set_mac(pkcs12.get(), pass.constData(), -1, NULL, 0,
				PKCS12_DEFAULT_ITER, EVP_sha256());

	BioByteArray b;
	i2d_PKCS12_bio(b, pkcs12.get());
	pki_openssl_error();
	file.write(b);
}

void pki_pkcs12::collect_properties(QMap<QString, QString> &prp) const
{
	if (!algorithm.isEmpty())
		prp["Algorithm"] = algorithm;
	if (!alias.isEmpty())
		prp["Friendly Name"] = alias;
}

// see https://www.rfc-editor.org/rfc/rfc8018 Appendix B.2 for possible encryption schemes
const QList<int> encAlgo::all_encAlgos(
{
	NID_pbe_WithSHA1And40BitRC2_CBC,
	NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
	NID_aes_256_cbc
});

/* AES-256-CBC: PBES2 with PBKDF2-HMAC-SHA256 for keys and certificates;
 * the legacy algorithms only when chosen (BTD-52) */
const int encAlgo::builtin_encAlgo(NID_aes_256_cbc);
int encAlgo::default_encAlgo(builtin_encAlgo);
QString encAlgo::exportName;

encAlgo::encAlgo(int nid) : encAlgo_nid(nid)
{
}

encAlgo::encAlgo(const QString &name) : encAlgo_nid(default_encAlgo)
{
	QString s(name);
	encAlgo_nid = OBJ_txt2nid(CCHAR(s.remove(QChar(' '))));
	ign_openssl_error();
}

QString encAlgo::name() const
{
	return QString(encAlgo_nid == NID_undef ? "" : OBJ_nid2sn(encAlgo_nid));
}

QString encAlgo::displayName() const
{
	QString n = name();
	if (legacy())
		n += QString(" (%1)").arg(QObject::tr("insecure"));
	return n;
}

QString encAlgo::description() const
{
	/* writePKCS12() protects the key of RC2-40 with 3DES */
	if (encAlgo_nid == NID_pbe_WithSHA1And40BitRC2_CBC)
		return QObject::tr("Encryption: certificates %1, key %2, "
			"MAC: SHA-1 (legacy)").arg(displayName())
			.arg(encAlgo(NID_pbe_WithSHA1And3_Key_TripleDES_CBC)
				.displayName());
	if (legacy())
		return QObject::tr("Encryption: %1, MAC: SHA-1 (legacy)")
			.arg(displayName());
	return QObject::tr("Encryption: %1 with PBES2/PBKDF2-HMAC-SHA256, "
			"MAC: HMAC-SHA256").arg(displayName());
}

int encAlgo::getEncAlgoNid() const
{
	return encAlgo_nid;
}

const encAlgo encAlgo::getDefault()
{
	return encAlgo(default_encAlgo);
}

void encAlgo::setDefault(const QString &def)
{
	default_encAlgo = encAlgo(def).encAlgo_nid;
}

const encAlgo encAlgo::forExport()
{
	return encAlgo(exportName.isEmpty() ?
			(QString)Settings["pkcs12_enc_algo"] : exportName);
}

encAlgo::ExportScope::ExportScope(const QString &name)
	: saved(exportName)
{
	exportName = name;
}

encAlgo::ExportScope::~ExportScope()
{
	exportName = saved;
}
