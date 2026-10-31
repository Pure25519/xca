/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/func.h"
#include "lib/load_obj.h"
#include "Options.h"
#include "SearchPkcs11.h"
#include "XcaWarning.h"
#include "Help.h"
#include "lib/pki_scard.h"
#include "lib/oid.h"
#include "lib/audit.h"
#include "lib/pki_pkcs12.h"
#include "lib/settings.h"
#include <openssl/objects.h>
#include <QFileDialog>
#include <QToolTip>
#include <QDir>

Options::Options(QWidget *parent)
	:QDialog(parent)
{
	setWindowTitle(XCA_TITLE);
	setupUi(this);
	mainwin->helpdlg->register_ctxhelp_button(this, "options");

	foreach(int nid, distname_nid) {
		QString n = OBJ_nid2ln(nid);
		extDNobj->addItem(n);
		expDNobj->addItem(n);
	}
	string_opts << "MASK:0x2002" << "pkix" << "nombstr" <<
			"utf8only" << "default";
	QStringList s;
	s << tr("Printable string or UTF8 (default)")
	  << tr("PKIX recommendation in RFC2459")
	  << tr("No BMP strings, only printable and T61")
	  << tr("UTF8 strings only (RFC2459)")
	  << tr("All strings");
	mbstring->addItems(s);
	mbstring->setCurrentIndex(string_opts.indexOf(
								QString(Settings["string_opt"])));

	transDnEntries->setText(transDnEntries->text()
			.arg(OBJ_nid2ln(NID_commonName))
			.arg(dn_translations[NID_commonName]));

	setDnString(Settings["mandatory_dn"], extDNlist);
	setDnString(Settings["explicit_dn"], expDNlist);

	suppress->setCheckState(Settings["suppress_messages"]);
	noColorize->setCheckState(Settings["no_expire_colors"]);
	transDnEntries->setCheckState(Settings["translate_dn"]);
	onlyTokenHashes->setCheckState(Settings["only_token_hashes"]);
	disableNetscape->setCheckState(Settings["disable_netscape"]);
	adapt_explicit_subj->setCheckState(Settings["adapt_explicit_subj"]);

	QStringList units;
	QString x = Settings["ical_expiry"];

	units << tr("Days") << "D" << tr("Weeks") << "W";
	ical_expiry_unit->addItemsData(units, x.right(1));
	x.chop(1);
	ical_expiry_num->setText(x);

	units << "%" << "%";
	x = QString(Settings["cert_expiry"]);
	cert_expiry_unit->addItemsData(units, x.right(1));
	x.chop(1);
	cert_expiry_num->setText(x);

	serial_len->setValue(Settings["serial_len"]);
	/* the default of PKCS#12 exports (BTD-175) */
	pkcs12Iterations->setRange(pki_pkcs12::minIterations,
				pki_pkcs12::maxIterations);
	pkcs12Iterations->setValue(
		((QString)Settings["pkcs12_iterations"]).toInt());

	pkcs11List->setModel(&pkcs11::libraries);
	pkcs11List->showDropIndicator();
	pkcs11List->setSelectionMode(QAbstractItemView::ExtendedSelection);

#ifdef APPSTORE_COMPLIANT
	onlyTokenHashes->hide();
	tabWidget->removeTab(2);
#endif
	loaded = shown();
}

QMap<QString, QString> Options::shown()
{
	auto yesno = [](const QCheckBox *b) {
		return QString(b->isChecked() ? "yes" : "no");
	};
	return QMap<QString, QString> {
		{ "suppress_messages", yesno(suppress) },
		{ "no_expire_colors", yesno(noColorize) },
		{ "translate_dn", yesno(transDnEntries) },
		{ "only_token_hashes", yesno(onlyTokenHashes) },
		{ "disable_netscape", yesno(disableNetscape) },
		{ "adapt_explicit_subj", yesno(adapt_explicit_subj) },
		{ "default_hash", hashAlgo->current().name() },
		{ "pkcs12_enc_algo", pkcs12EncAlgo->current().name() },
		{ "mandatory_dn", getDnString(extDNlist) },
		{ "explicit_dn", getDnString(expDNlist) },
		{ "string_opt", string_opts.value(mbstring->currentIndex()) },
		{ "pkcs11path", pkcs11::libraries.getPkcs11Provider() },
		{ "cert_expiry", cert_expiry_num->text() +
			cert_expiry_unit->currentItemData().toString() },
		{ "ical_expiry", ical_expiry_num->text() +
			ical_expiry_unit->currentItemData().toString() },
		{ "serial_len", QString::number(serial_len->value()) },
		{ "pkcs12_iterations",
			QString::number(pkcs12Iterations->value()) },
	};
}

Options::~Options()
{
	delete searchP11;
}

void Options::on_extDNadd_clicked()
{
	extDNlist->addItem(extDNobj->currentText());
}

void Options::on_extDNdel_clicked()
{
	extDNlist->takeItem(extDNlist->currentRow());
}

void Options::on_expDNadd_clicked()
{
	expDNlist->addItem(expDNobj->currentText());
}

void Options::on_expDNdel_clicked()
{
	expDNlist->takeItem(expDNlist->currentRow());
}

void Options::on_expDNdefault_clicked()
{
	setDnString(Settings.defaults("explicit_dn"), expDNlist);
}

void Options::setDnString(QString dn, QListWidget *w)
{
	QStringList dnl;

	if (!dn.isEmpty())
		dnl = dn.split(",");
	w->clear();
	for (int i=0; i < dnl.count(); i++) {
		int nid = OBJ_sn2nid(CCHAR(dnl[i]));
		w->addItem(OBJ_nid2ln(nid));
	}
}

QString Options::getDnString(QListWidget *w)
{
	QStringList dn;

	for (int j=0; j<w->count(); j++) {
		int nid = OBJ_ln2nid(CCHAR(w->item(j)->text()));
		dn << QString(OBJ_nid2sn(nid));
	}
	return dn.join(",");
}

int Options::exec()
{
	if (QDialog::exec() == QDialog::Rejected)
		return QDialog::Rejected;

	/* Only what the user changed is stored: a stored setting is a
	 * choice, not the default the dialog showed (BTD-52, BTD-187),
	 * each with its settings.update entry (BTD-224) */
	QMap<QString, QString> now = shown(), changed;
	for (auto i = now.cbegin(); i != now.cend(); ++i) {
		if (loaded.value(i.key()) != i.value())
			changed[i.key()] = i.value();
	}
	try {
		Settings.update(ServiceContext::localUser(
				ServiceContext::gui), changed);
	} catch (errorEx &err) {
		XCA_ERROR(err);
		return QDialog::Rejected;
	}
	return QDialog::Accepted;
}

void Options::on_addButton_clicked(void)
{
	load_pkcs11 l;
	QString fname;

	fname = QFileDialog::getOpenFileName(this, l.caption,
		getLibDir(), l.filter, nullptr, QFileDialog::DontResolveSymlinks);

	addLib(fname);
}

void Options::addLib(QString fname)
{
	fname = QDir::cleanPath(fname);
	pkcs11_lib *l = pkcs11::libraries.add_lib(fname);

	if (searchP11 && l)
		QToolTip::showText(searchP11->mapToGlobal(
			QPoint(0,0)), l->driverInfo().trimmed());
}

void Options::on_removeButton_clicked(void)
{
	QList<int> indexes;
	foreach(QModelIndex i, pkcs11List->selectionModel()->selectedIndexes())
		indexes << i.row();

	/* Delete from highest to lowest index */
	std::sort(indexes.begin(), indexes.end(), std::greater<int>());
	foreach(int i, indexes)
		pkcs11List->model()->removeRow(i);
}

void Options::on_searchPkcs11_clicked(void)
{
	if (!searchP11) {
		searchP11 = new SearchPkcs11(this, getLibDir());
		connect(searchP11, SIGNAL(addLib(QString)),
			this, SLOT(addLib(QString)));
	}
	searchP11->show();
}
