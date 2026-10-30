/* vi: set sw=4 ts=4:
 *
 * Import and export as service functions (BTD-34, doc/service-pattern.md):
 * database_model::importItems(ctx, ImportSpec) and
 * db_base::exportItems(ctx, ExportSpec).
 */

#ifndef __IMPORTEXPORT_H
#define __IMPORTEXPORT_H

#include <QByteArray>
#include <QList>
#include <QMap>
#include <QString>
#include <QStringList>

class pki_base;
class pki_export;

/* What to import. Files, data and items may be combined. */
class ImportSpec
{
  public:
	/* Files to read, each probed like the import dialog does */
	QStringList files{};
	/* The content of one file: PEM (any number of objects), DER,
	 * PKCS#7, PKCS#12, PKCS#8, PVK, SSH or an XCA template */
	QByteArray data{};
	/* Describes data in internal names and comments, e.g. the
	 * file name of an upload */
	QString dataName{};
	/* Objects read before, e.g. by the import dialog.
	 * importItems() takes them over: stored or deleted */
	QList<pki_base *> items{};
	/* If set, a failed importItems() hands the objects of items it
	 * neither stored nor deleted back in this list instead of deleting
	 * them, e.g. to keep them in the import dialog (BTD-114). An object
	 * that a store step failed on is deleted all the same
	 * (db_base::insertPKI()). */
	QList<pki_base *> *unstored{};
	/* pass:, env:, file:, fd: or stdin for encrypted input. Empty:
	 * PwDialogCore asks (the GUI dialog, or the headless source of
	 * the purpose ImportPassword) */
	QString passwordSource{};
};

class ImportResult
{
  public:
	/* New in the database, in import order */
	QList<pki_base *> created{};
	/* Already in the database; the imported copy was dropped */
	QList<pki_base *> existing{};
	/* Files (or dataName) that contained no PKI object */
	QStringList failedFiles{};

	QList<pki_base *> all() const
	{
		return created + existing;
	}
};

/* What to export */
class ExportSpec
{
  public:
	/* Non-owning, in selection order; chain formats start at the
	 * first item. Formats for all certificates (F_UNUSABLE, F_ALL,
	 * F_UNREVOKED) still need one item of the model. */
	QList<pki_base *> items{};
	/* One of pki_export::select() for the items' type */
	const pki_export *format{};
	/* pass:, env:, file:, fd: or stdin for an encrypting format
	 * (F_CRYPT). Empty: PwDialogCore asks (the GUI dialog, or the
	 * headless source of the purpose ExportPassword) */
	QString passwordSource{};
	/* Target file, created or truncated; private keys get mode 0600.
	 * Empty: exportItems() only returns the bytes */
	QString fileName{};
	/* With fileName empty: the file the caller writes the returned
	 * bytes to (the bxc-pki command line publishes them after its
	 * commit, BTD-42); the audit param file names it */
	QString publishedFile{};
	/* The clipboard text of the items (Ctrl+C, drag) instead of
	 * format: pki_base::pem() in the formats of the settings
	 * KeyFormat and CertFormat */
	bool clipboard{};
	/* PKCS#12 encryption, a name of encAlgo::all_encAlgos, e.g.
	 * PBE-SHA1-3DES for a legacy reader. Empty: the setting
	 * pkcs12_enc_algo, by default AES-256-CBC (BTD-52) */
	QString pkcs12Algorithm{};
	/* Encoding of ML-DSA private keys (RFC 9881): "both" (seed and
	 * expanded key), "seed" or "expanded", e.g. expanded for a reader
	 * without seed support. Empty: OpenSSL's default, both, or the
	 * expanded key of a key imported without seed (BTD-16) */
	QString privateKeyFormat{};
	/* Out, optional: the ML-DSA encoding written per private key, by
	 * its item id, as the audit entry key.export_private names it
	 * (the bxc-pki command line reports it, BTD-42) */
	QMap<QString, QString> *mlDsaWritten{};
};

/* "certificate", "key", "request", "crl", "template": the audit object
 * type of an item */
QString auditObjectType(const pki_base *pki);
/* The message for an item that importItems() found in the database */
QString importExistsMessage(const pki_base *existing);

#endif
