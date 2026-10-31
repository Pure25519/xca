/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __EXPORTDIALOG_H
#define __EXPORTDIALOG_H

#include "ui_ExportDialog.h"
#include "lib/pki_export.h"
#include "lib/importexport.h"
#include <QModelIndexList>

class QPixmap;
class pki_base;

class ExportDialog: public QDialog, public Ui::ExportDialog
{
	Q_OBJECT

  protected:
	QString filter{}, savedFile{}, filenameLabelOrig{};
	QList<const pki_export*> alltypes;
	QList<pki_base *> pkis{};
	void mlDsaHelp(const pki_export *x);

  public:
	ExportDialog(QWidget *w, const QString &title, const QString &filt,
		     const QModelIndexList &indexes, const QPixmap &img,
		     QList<const pki_export*> types,
		     const QString &help_ctx = QString());
	~ExportDialog();
	const pki_export *export_type(int idx = -1) const;
	/* The chosen format and file name for the items; with
	 * "separate files" the file name is the directory */
	ExportSpec exportSpec(const QList<pki_base *> &items) const;
	/* True if the format writes an ML-DSA private key of the items:
	 * only then is the ML-DSA encoding offered (BTD-190) */
	static bool mlDsaApplies(const QList<pki_base *> &items,
		const pki_export *xport);
	static bool mayWriteFile(const QString &fname, bool inSeparateFiles);
	void setupExportFormat(int disable_flag);

  public slots:
	void on_fileBut_clicked();
	void on_separateFiles_clicked(bool checked);
	void on_exportFormat_activated(int);
	void on_exportFormat_highlighted(int index);
	void on_mlDsaFormat_currentIndexChanged(int);
	void accept();
};

#endif
