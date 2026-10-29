/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __IMPORTMULTI_H
#define __IMPORTMULTI_H

#include "ui_ImportMulti.h"
#include "lib/db_token.h"
#include "lib/db_base.h"
#include <QList>

class pki_x509;
class pki_key;

class ImportMulti: public QDialog, private Ui::ImportMulti
{
	Q_OBJECT

	private:
		slotid slot{};
		db_token *mcont{};
		void importError(QStringList failed);
		pki_base *importOne(pki_base *pki, QString *code,
				QString *error);

	public:
		ImportMulti(QWidget *parent);
		~ImportMulti();
		void addItem(pki_base *pki);
		pki_base *getSelected();
		pki_base *import(const QModelIndex &idx);
		pki_base *import(pki_base *pki);
		void importIndexes(const QModelIndexList &indexes);
		/* Stores the items through database_model::importItems()
		 * (BTD-34), takes them over, reports items already in the
		 * database and errors; returns the stored items */
		static QList<pki_base *> importItems(QList<pki_base *> items);
		void execute(int force=0, QStringList failed = QStringList());
		int entries();
		void tokenInfo(const slotid &s);
		void dragEnterEvent(QDragEnterEvent *event);
		void dropEvent(QDropEvent *event);
		bool openDB() const;
		void showDetail(pki_base *pki);
		void showDetail(const QModelIndex &idx);

	public slots:
		void on_butRemove_clicked();
		void on_butImport_clicked();
		void on_butDetails_clicked();
		void on_butOk_clicked();
		void on_deleteToken_clicked();
		void on_renameToken_clicked();
};

#endif
