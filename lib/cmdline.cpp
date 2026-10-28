/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QString>
#include <QFile>
#include <stdio.h>

#include "func.h"
#include "database_model.h"
#include "debug_info.h"
#include "pki_multi.h"
#include "pki_evp.h"
#include "pki_base.h"
#include "pki_x509.h"
#include "pki_crl.h"
#include "arguments.h"
#include "pki_export.h"
#include "PwDialogCore.h"
#include "BioByteArray.h"
#include "db_x509.h"
#include "db_crl.h"
#include "audit.h"

static const char *xca_name = "xca";
static void cmd_version(FILE *fp)
{
	console_write(fp, QString(XCA_TITLE "\nVersion %1\n")
				.arg(version_str(false)).toUtf8());
}

static int cmd_help(int exitcode = EXIT_SUCCESS, const char *msg = NULL)
{
	FILE *fp = exitcode == EXIT_SUCCESS ? stdout : stderr;
	QString s;

	cmd_version(fp);
	s = QString("\nUsage %1 <options> <file-to-import> ...\n\n%2\n")
				.arg(xca_name).arg(arguments::help());
	if (msg)
		s += QString("\nError: %1\n").arg(msg);

	console_write(fp, s.toUtf8());
	return exitcode;
}

/* A --password or --sqlpass value as source: without a known prefix
 * the value is the password itself (upstream behaviour) */
static QString password_source(const QString &arg)
{
	if (arg.isEmpty() || PwDialogHeadless::isSource(arg))
		return arg;
	return QString("pass:") + arg;
}

static bool compare_pki_base(pki_base* a, pki_base* b)
{
	return (a->getSqlItemId().toULongLong() <
		b->getSqlItemId().toULongLong());
}

int read_cmdline(int argc, char *argv[], bool console_only,
			pki_multi **_cmdline_items)
{
	pki_multi *cmdline_items;
	/* A failure reported here sets EXIT_FAILURE and the remaining
	 * options still run; an exception ends the command and main()
	 * returns EXIT_FAILURE */
	int exitcode = EXIT_SUCCESS;

	if (argc > 0)
		xca_name = argv[0];
	arguments cmd_opts(argc, argv);
	QString dbpass = password_source(cmd_opts["password"]);
	QString sqlpass = password_source(cmd_opts["sqlpass"]);
	PwDialogHeadless *headless = PwDialogCore::headless();
	Passwd sqlpw;

	if (console_only) {
		/* Without a GUI every request of these purposes is answered
		 * from the source; one nobody provided ends the command */
		headless->setInteractive(cmd_opts.has("interactive"));
		headless->setSource(pass_info::DatabasePassword, dbpass);
		headless->setSource(pass_info::KeyPassword, dbpass);
		headless->setSource(pass_info::SqlPassword, sqlpass);
		if (!sqlpass.isEmpty())
			sqlpw = headless->secret(pass_info::SqlPassword);
	} else {
		/* The GUI uses the password once, to unlock the database */
		if (!dbpass.isEmpty())
			PwDialogCore::cmdline_passwd =
				PwDialogHeadless::readSource(dbpass);
		if (!sqlpass.isEmpty())
			sqlpw = PwDialogHeadless::readSource(sqlpass);
	}

	if (cmd_opts.has("verbose")) {
		QString all = cmd_opts["verbose"];
		debug_info::set_debug(all.isEmpty() ? QString("all") : all);
	}
	if (console_only) {
		database_model::open_without_password = true;
		ServiceContext::processChannel = ServiceContext::cli;
	}

	if (cmd_opts.has("no-native-dialogs"))
		QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs, true);

	if (cmd_opts.has("database"))
		Database.open(cmd_opts["database"], sqlpw);

	*_cmdline_items = cmdline_items = new pki_multi();

	foreach(QString file, cmd_opts.getFiles()) {
		qDebug() << "Probe" << file;
		cmdline_items->probeAnything(file);
	}
	QStringList names = cmd_opts["import-names"].split(";");
	foreach(pki_base *pki, cmdline_items->get()) {
		if (names.isEmpty())
			break;
		QString name = names.takeFirst();
		if (!name.isEmpty())
			pki->setIntName(name);
	}
	if (cmdline_items->failed_files.size() > 0) {
		XCA_WARN(QString("Failed to import from '%1'")
			.arg(cmdline_items->failed_files.join("' '")));
	}
	if (cmd_opts.needDb() && !Database.isOpen()) {
		/* We need a database for the following operations
		 * but there is none, yet. Try the default database */
		try {
			Database.open(QString());
		} catch (errorEx &err) {
			return cmd_help(EXIT_FAILURE, CCHAR(err.getString()));
		} catch (enum open_result opt) {
			static const char * const msg[] = {
				/* pw_cancel */ "Password input aborted",
				/* pw_ok     */ "Password accepted??",
				/* pw_exit   */ "Exit selected",
				/* open_abort*/ "No database given",
			};
			return cmd_help(EXIT_FAILURE, msg[opt]);
		}
	}
	database_model::open_without_password = false;

	if (cmd_opts.has("list-curves")) {
		QStringList list;
		foreach(const builtin_curve &c, builtinCurves) {
			list << QString(COL_YELL "%1" COL_RESET "%2")
					.arg(OBJ_nid2sn(c.nid), -26)
					.arg(c.comment);
		}
		console_write(stdout, list.join("\n").toUtf8() + '\n');
	}
	if (cmd_opts.has("list-items")) {
		QStringList list;
		QList<pki_base*> items = Store.getAll<pki_base>();
		std::sort(items.begin(), items.end(), compare_pki_base);
		foreach(pki_base *pki, items) {
			list << QString(COL_YELL "%1 " COL_GREEN "%2 "
					COL_RESET "%3")
					.arg(pki->getSqlItemId().toString(), 7)
					.arg(pki->getTypeString(), -27)
					.arg(pki->getIntName());
		}
		console_write(stdout, list.join("\n").toUtf8() + '\n');
	}
	if (!cmd_opts["index"].isEmpty()) {
		qDebug() << cmd_opts["index"];
		db_x509 *certs = Database.model<db_x509>();
		certs->writeIndex(cmd_opts["index"], false);
		XCA_INFO(QObject::tr("Index file written to '%1'")
					.arg(cmd_opts["index"]));
	}
	if (!cmd_opts["hierarchy"].isEmpty()) {
		qDebug() << cmd_opts["hierarchy"];
		db_x509 *certs = Database.model<db_x509>();
		certs->writeIndex(cmd_opts["hierarchy"], true);
		XCA_INFO(QObject::tr("Index hierarchy written to '%1'")
					.arg(cmd_opts["hierarchy"]));
	}
	/* Both fail closed: any error means exit code 1 */
	if (cmd_opts.has("audit-verify")) {
		try {
			AuditVerifyResult r = AuditLog::verify();
			console_write(stdout, r.toJson() + '\n');
			if (!r.ok())
				exitcode = EXIT_FAILURE;
		} catch (errorEx &err) {
			QVariantMap m { { "ok", false },
					{ "error", err.getString() } };
			console_write(stdout, AuditLog::canonicalJson(m) + '\n');
			exitcode = EXIT_FAILURE;
		}
	}
	if (cmd_opts.has("audit-export")) {
		QString filename = cmd_opts["audit-export"];
		try {
			QByteArray lines = AuditLog::exportJsonLines();
			if (filename == "-") {
				console_write(stdout, lines);
			} else {
				XFile f(filename);
				if (!f.open_write() ||
				    f.write(lines) != lines.size())
					throw errorEx(QObject::tr("Failed to write the audit log to '%1'")
							.arg(filename));
				f.close();
			}
		} catch (errorEx &err) {
			XCA_ERROR(err);
			exitcode = EXIT_FAILURE;
		}
	}
	if (cmd_opts.has("help"))
		cmd_help();

	if (cmd_opts.has("version"))
		cmd_version(stdout);

	if (cmd_opts.has("keygen")) {
		keyjob task(cmd_opts["keygen"]);
		if (!task.isValid()) {
			Database.close();
			throw errorEx(QObject::tr("Unknown key type %1")
					.arg(cmd_opts["keygen"]));
		}
		db_key *keys = Database.model<db_key>();
		pki_key *pki = keys->newKey(task, cmd_opts["name"]);
		if (pki)
			cmdline_items->append_item(pki);
	}
	if (cmd_opts.has("issuers")) {
		QStringList out;
		db_x509 *certs = Database.model<db_x509>();
		QList<pki_x509*>issuers = certs->getAllIssuers();
		std::sort(issuers.begin(), issuers.end(), compare_pki_base);
		foreach(pki_x509 *iss, issuers) {
			pki_key *key = iss->getRefKey();
			QString keytype = key ? key->getTypeString() : "";
			out << QString(COL_YELL "%1 " COL_GREEN "%2 "
					COL_RESET "%3")
				.arg(iss->getSqlItemId().toULongLong(), 7)
				.arg(keytype, -13)
				.arg(iss->getIntName());
		}
		console_write(stdout, out.join("\n").toUtf8() + '\n');
	}
	if (cmd_opts.has("crlgen")) {
		db_crl *crls = Database.model<db_crl>();
		db_x509 *certs = Database.model<db_x509>();
		QList<pki_x509*>issuers = certs->getAllIssuers();
		pki_x509 *issuer = NULL;
		QString ca = cmd_opts["crlgen"];
		foreach(pki_x509 *iss, issuers) {
			if (iss->getIntName() == ca ||
			    iss->getSqlItemId().toString() == ca)
			{
				issuer = iss;
				break;
			}
		}
		if (!issuer) {
			XCA_ERROR(QString("Issuer '%1' not found")
					.arg(cmd_opts["crlgen"]));
			exitcode = EXIT_FAILURE;
		} else {
			crljob task(issuer);
			pki_crl *crl = crls->newCrl(ServiceContext::localUser(
					ServiceContext::cli), task, cmd_opts["name"]);
			crls->createSuccess(crl);
			cmdline_items->append_item(crl);
		}
	}
	if (!cmd_opts["select"].isEmpty()) {
		foreach(QString item, cmd_opts["select"].split(",")) {
			bool ok;
			qDebug() << "Select" << item;
			qulonglong id = item.toULongLong(&ok);
			pki_base *pki = Store.lookupPki<pki_base>(QVariant(id));
			if (pki)
				cmdline_items->append_item(pki);
		}
	}

	BioByteArray bba, bbafile;
	foreach(pki_base *pki, cmdline_items->get()) {
		QString filename = pki->getFilename();
		if ((cmd_opts.has("text") || cmd_opts.has("print")) &&
		    filename.size() > 0)
		{
			bba += QString("\n" COL_GREEN COL_UNDER "File: %1"
				COL_RESET "\n").arg(filename).toUtf8();
		}
		if (cmd_opts.has("print"))
			pki->print(bba, pki_base::print_coloured);
		if (cmd_opts.has("text"))
			pki->print(bba, pki_base::print_openssl_txt);
		if (cmd_opts.has("pem-file"))
			pki->print(bbafile, pki_base::print_pem);
		else if (cmd_opts.has("pem"))
			pki->print(bba, pki_base::print_pem);
	}
	if (bba.size() > 0)
		console_write(stdout, bba);

	if (bbafile.size() > 0)
	{
		QString filename = cmd_opts["pem-file"];
		XFile f(filename);
		if (f.open_write()) {
			f.write(bbafile);
		} else {
			XCA_ERROR(QObject::tr("Failed to write PEM data to '%1'")
					.arg(filename));
			exitcode = EXIT_FAILURE;
		}
		f.close();
	}
	if (cmd_opts.has("import")) {
		ImportSpec spec;
		/* importItems() takes the items over */
		spec.items << cmdline_items;
		*_cmdline_items = nullptr;
		try {
			ImportResult result = Database.importItems(
				ServiceContext::localUser(ServiceContext::cli),
				spec);
			foreach(pki_base *pki, result.existing)
				XCA_INFO(importExistsMessage(pki));
		} catch (errorEx &err) {
			XCA_ERROR(err);
			exitcode = EXIT_FAILURE;
		}
	}
	return exitcode;
}

