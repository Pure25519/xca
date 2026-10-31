/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "settings.h"
#include "func.h"
#include "sql.h"
#include "pki_key.h"
#include "digest.h"
#include "pki_pkcs12.h"
#include "pki_export.h"
#include "audit.h"

#include <QDebug>
#include <QDir>
#include <QFile>
#include <openssl/asn1.h>

settings Settings;

svalue::svalue(settings *s, const QString &k)
	:  setting(s), key(k)
{
}

QString svalue::get() const
{
	return setting ? setting->get(key) : QString();
}

void svalue::set(const QString &val)
{
	if (setting)
		setting->set(key, val);
}

settings::settings()
{
	hostspecific = QStringList({ "pkcs11path", "workingdir", "mw_geometry" });
}

const QMap<QString, QString> settings::defaults() const
{
	return QMap<QString, QString> {
		{ "mandatory_dn", "" },
		{ "explicit_dn", "C,ST,L,O,OU,CN,emailAddress" },
		{ "string_opt", "MASK:0x2002" },
		{ "workingdir", getHomeDir() + "/" },
		/* compiled-in, not the statics that setAction() fills from
		 * the database opened before (BTD-174) */
		{ "default_hash", digest::getBuiltinDefault().name() },
		{ "pkcs12_enc_algo", encAlgo::getBuiltinDefault().name() },
		/* PBKDF2 iterations of a PKCS#12 export (BTD-175) */
		{ "pkcs12_iterations",
			QString::number(pki_pkcs12::minIterations) },
		{ "ical_expiry", "1W" },
		{ "cert_expiry", "80%" },
		{ "serial_len", "64" },
		{ "fp_separator", ":" },
		{ "fp_digits", "2" },
		{ "hide_unusable", "no" },
		{ "KeyFormat", QString::number(DEFAULT_KEY_CLIPBOARD_TYPE) },
		{ "CertFormat", QString::number(DEFAULT_CERT_CLIPBOARD_TYPE) },
	};
}

void settings::clear()
{
	loaded = false;
	values.clear();
	db_keys.clear();
	legacyOptionflags.clear();
	keyjob::defaultjob = keyjob();
	const QMap<QString, QString> def = defaults();
	for(QString key : def.keys())
		setAction(key, def[key]);
	/* A database that stays open (e.g. after a failed password change)
	 * keeps its stored values: the statics above are read directly */
	load_settings();
}

void settings::setAction(const QString &key, const QString &value)
{
	if (key == "string_opt")
		ASN1_STRING_set_default_mask_asc((char*)CCHAR(value));
	else if (key == "default_hash")
		digest::setDefault(value);
	else if (key == "pkcs12_enc_algo")
		encAlgo::setDefault(value);
	else if (key == "defaultkey")
		keyjob::defaultjob = keyjob(value);
	else if (key == "optionflags") {
		/* Reading the settings happens before the database password
		 * is checked: memory only, migrateOptionflags() stores them
		 * (BTD-137). Before, the row was deleted and committed here. */
		legacyOptionflags = value;
		foreach(QString flag, value.split(",")) {
			if (flag == "dont_colorize_expiries")
				flag = "no_expire_colors";
			setAction(flag, "yes");
		}
		return;
	}
	values[key] = value;
}

void settings::migrateOptionflags()
{
	load_settings();
	if (legacyOptionflags.isEmpty())
		return;
	XSqlQuery q;
	Transaction;
	if (!TransBegin())
		return;
	foreach(QString flag, legacyOptionflags.split(",", Qt::SkipEmptyParts)) {
		if (flag == "dont_colorize_expiries")
			flag = "no_expire_colors";
		/* "yes" in memory already, but not stored: not in db_keys */
		set(flag, "yes");
	}
	SQL_PREPARE(q, "DELETE FROM settings WHERE key_='optionflags'");
	q.exec();
	if (q.lastError().isValid()) {
		qWarning() << "optionflags not migrated:" << q.lastError().text();
		TransRollback();
		return;
	}
	if (!TransCommit())
		return;
	db_keys.removeAll("optionflags");
	legacyOptionflags.clear();
}

QString settings::defaults(const QString &key)
{
	return defaults()[key];
}

void settings::load_settings()
{
	if (loaded || !QSqlDatabase::database().isOpen())
		return;
	XSqlQuery q("SELECT key_, value FROM settings");
	while (q.next()) {
		QString key = q.value(0).toString().simplified();
		QString value = q.value(1).toString();
		QStringList l = key.split(":");
		if (l.size() == 2 && l[1] != hostId())
			continue;	// Skip key with non-matching host ID
		if (l[0] == "workingdir") {
			if (!QDir(value).exists())
				continue; // Skip non-existing working-dir
			if (!value.isEmpty() && !value.endsWith("/"))
				value += "/";
			if (value.isEmpty())
				value = getHomeDir() + "/";
		}
		db_keys << key;		// Key with host ID
		setAction(l[0], value);	// Key without host ID
	}
	loaded = true;
}

QString settings::get(QString key)
{
	load_settings();
	if (key == "schema" && QSqlDatabase::database().isOpen()) {
		XSqlQuery q("SELECT value FROM settings WHERE key_='schema'");
		if (q.first())
			setAction("schema", q.value(0).toString());
	}
	return values.contains(key) ? values[key] : QString();
}

void settings::set(QString key, QString value)
{
	XSqlQuery q;
	load_settings();
	QString origkey = key;

	if (key == "workingdir") {
		if (!QDir(value).exists())
			return;
		value = relativePath(value);
		if (!value.isEmpty() && !value.endsWith("/"))
			value += "/";
	}
	if (hostspecific.contains(key))
		key += QString(":%1").arg(hostId());
	if (db_keys.contains(key) && values[origkey] == value)
		return;

	Transaction;
	if (!TransBegin())
		return;

	bool insert = !db_keys.contains(key);
	if (insert) {
		SQL_PREPARE(q, "INSERT INTO settings (value, key_) VALUES (?,?)");
	} else {
		SQL_PREPARE(q, "UPDATE settings SET value=? WHERE key_=?");
	}
	q.bindValue(0, value);
	q.bindValue(1, key);
	/* not stored: memory keeps the stored value, and a caller's
	 * transaction rolls back with this write (BTD-52) */
	if (!q.exec()) {
		qWarning() << "Setting" << key << "not stored:"
			<< q.lastError().text();
		TransRollback();
		return;
	}
	/* finish() shows a failed COMMIT */
	if (!TransCommit())
		return;
	bool hadValue = values.contains(origkey);
	QString oldValue = values.value(origkey);
	if (insert)
		db_keys << key;
	setAction(origkey, value);
	/* the caller's transaction may still roll back (BTD-130) */
	DbTransaction::onRollback([this, key, origkey, insert, hadValue,
				oldValue]() {
		if (insert)
			db_keys.removeAll(key);
		if (hadValue)
			setAction(origkey, oldValue);
		else
			values.remove(origkey);
	});
}

/* The options of the Options dialog (the keys of its shown()) and the
 * audit checkpoint interval: their values go into the audit log in
 * clear (BTD-224) */
static const QStringList clearSettings {
	"adapt_explicit_subj", "cert_expiry", "default_hash",
	"disable_netscape", "explicit_dn", "ical_expiry", "mandatory_dn",
	"no_expire_colors", "only_token_hashes", "pkcs11path",
	"pkcs12_enc_algo", "serial_len", "string_opt", "suppress_messages",
	"translate_dn",
	/* not in the dialog, but no secret either (BTD-100) */
	"audit_checkpoint_interval",
};

static bool clearSetting(const QString &key)
{
	/* never a password or the password hash, whatever the list says */
	if (key.contains("pass", Qt::CaseInsensitive) || key == "pwhash")
		return false;
	return clearSettings.contains(key);
}

void settings::update(const ServiceContext &ctx,
			const QMap<QString, QString> &changes)
{
	Transaction;
	TransThrow();
	for (auto i = changes.cbegin(); i != changes.cend(); ++i) {
		QString old = get(i.key());
		set(i.key(), i.value());
		QString now = get(i.key());
		/* set() skips a value it does not take (a workingdir
		 * that does not exist) */
		if (now == old)
			continue;
		AuditParams params;
		params.set("setting", hostspecific.contains(i.key()) ?
			QString("%1:%2").arg(i.key()).arg(hostId()) : i.key());
		if (clearSetting(i.key()))
			params.set("old_value", old).set("new_value", now);
		else
			params.set("redacted", true);
		AuditLog::append(ctx, AuditLog::actionSettingsUpdate,
				"database", QString(), params);
	}
	TransCommitThrow();
}
