/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DB_BASE_H
#define __DB_BASE_H

#include <typeinfo>
#include "base.h"
#include "pki_base.h"
#include "headerlist.h"

#include <QStringList>
#include <QAbstractItemModel>
#include <QHash>

#define X_XCA_DRAG_DATA "application/x-xca-drag-data"

class QContextMenuEvent;
class XcaTreeView;
class NewX509;
class ServiceContext;
class ExportSpec;
class Passwd;
class pki_key;

/* What db_base::deleteItems() did (BTD-35) */
class DeleteResult
{
  public:
	class Deleted
	{
	  public:
		QString objectType{};   // audit object type, e.g. "certificate"
		QString id{};           // item id the object had
		QString name{};
	};
	/* The deleted objects, in the order of the call */
	QList<Deleted> deleted{};
	/* Objects that stay and referred to a deleted one, as XCA always
	 * handled them: certificates and requests that lost their private
	 * key, certificates that lost their issuer (they move to another
	 * certificate with the issuer's subject and key, if there is one),
	 * CRLs that lost their issuer */
	QList<pki_base *> dependents{};
	/* Revocation rows of deleted CA certificates that were removed */
	int revocations{};
};

class db_base: public QAbstractItemModel
{
	Q_OBJECT

	protected:
		a1time minuteMarker{}, hourMarker{};
		QTimer maintenanceTimer{};
		QList<enum pki_type> pkitype{};
		QList<enum pki_type> pkitype_depends{};
		QString class_name{};
		/* Sql table containing the 'hash' of this items */
		QString sqlHashTable{};
		dbheaderList allHeaders{};
		int colResizing{};
		bool treeview{ true };
		pki_base *rootItem{};
		pki_base *treeItem{};
		QVariant selected{};

		void _writePKI(pki_base *pki, bool overwrite);
		/* Removes pki from the database, the store and the view,
		 * moves or unlinks the objects that refer to it and frees
		 * it. No question, no token, no audit entry: the caller
		 * owns the transaction. Throws errorEx on a database error. */
		void removeItem(pki_base *pki);
		/* UPDATE of the items row (name, comment); the caller owns
		 * the transaction. Throws serviceError database_error. */
		static void writeNameComment(pki_base *pki);
		virtual dbheaderList getHeaders();
		QString sqlItemSelector();
		bool isValidCol(int col) const;

	public:
		void restart_timer();

		virtual pki_base *newPKI(enum pki_type type = none);
		db_base(const char *classname);
		virtual void updateHeaders();
		virtual ~db_base();
		/* Stores pki and returns it. A failed write throws the typed
		 * error of throwSqlError() and leaves pki with the caller,
		 * not stored and without id (BTD-50); it used to delete it
		 * and return NULL. */
		virtual pki_base *insertPKI(pki_base *pki);
		/* Takes an object whose insert was rolled back out of the
		 * views and the store again; it loses its id (BTD-142).
		 * Memory only: writes nothing to the database (BTD-130) */
		void unstore(pki_base *pki);
		/* Puts an object whose row was just inserted into the store
		 * and the views; unstore() if the transaction rolls back
		 * (BTD-130). The object then belongs to the caller again. */
		void storeInMemory(pki_base *pki);
		pki_base *getByName(QString desc);
		pki_base *getByReference(pki_base *refpki);
		virtual void loadContainer();
		void reloadContainer(const QList<enum pki_type> &typelist);
		virtual pki_base* insert(pki_base *item);
		virtual void inToCont(pki_base *pki);
		/* Takes pki out of the views and relinks the objects that
		 * referred to it, in memory only (BTD-130) */
		virtual void remFromCont(pki_base *pki);
		/* pki is an object of this list stored in the database */
		bool isStored(const pki_base *pki) const;
		void changeView();
		/* The export flags (F_*) the items do not support */
		int exportFlags(const QList<pki_base *> &items) const;
		virtual int exportFlags(pki_base *) const
		{
			return 0;
		}
		/* Exports the items (BTD-34). Throws serviceError for a
		 * rejected spec and errorEx for anything else; one audit entry
		 * object.export per exported object and key.export_private per
		 * private key in the output, or one object.export failure. No
		 * question or message; call it outside a transaction.
		 * Returns the exported bytes, also when they went to a file. */
		QByteArray exportItems(const ServiceContext &ctx,
			const ExportSpec &spec);
		/* The checks of exportItems() before it asks for a password
		 * (items, format, PKCS#12 algorithm, ML-DSA key format):
		 * throws their serviceError, writes nothing (bxc-pki
		 * --plan, BTD-211) */
		void checkExportSpec(const ExportSpec &spec) const;
		/* The writers behind exportItems(): no prompt, no audit */
		virtual void writeItem(pki_base *pki, const pki_export *xport,
			QIODevice &file, const Passwd &pass) const;
		virtual void writeItems(const QList<pki_base *> &items,
			const pki_export *xport, QIODevice &file,
			const Passwd &pass) const;
		/* The objects a format writes for the items, e.g. the chain */
		virtual QList<pki_base *> exportedObjects(
			const QList<pki_base *> &items,
			const pki_export *xport) const;
		/* The private keys a format writes for the items */
		virtual QList<pki_key *> exportedPrivateKeys(
			const QList<pki_base *> &items,
			const pki_export *xport) const;
		/* The format of pki_base::pem() for the clipboard text, or
		 * NULL if it never contains a private key */
		virtual const pki_export *clipboardFormat() const
		{
			return nullptr;
		}

		void dump(const QString &dirname) const;
		QModelIndex index(int row, int column,
				const QModelIndex &parent = QModelIndex()) const;
		QModelIndex index(pki_base *pki) const;
		QModelIndex parent(const QModelIndex &index) const;
		int rowCount(const QModelIndex &parent = QModelIndex()) const;
		int allItemsCount() const
		{
			return rootItem->childCount();
		}
		int columnCount(const QModelIndex &parent) const;
		QVariant data(const QModelIndex &index, int role) const;
		QVariant headerData(int section, Qt::Orientation orientation,
				int role) const;
		Qt::ItemFlags flags(const QModelIndex &index) const;
		/* The inline editor of the view (F2): rename() */
		bool setData(const QModelIndex &index, const QVariant &value, int role);
		/* Service functions (BTD-35). No question or message; call
		 * them outside a transaction. Rejections throw serviceError. */
		/* object.rename: one entry with old_name and name; nothing
		 * is written when the name does not change */
		virtual void rename(const ServiceContext &ctx, pki_base *pki,
				const QString &name);
		/* Name and comment (Properties, detail dialogs): one entry
		 * object.rename and one object.update_comment for what
		 * changed, in one transaction */
		void updateProperties(const ServiceContext &ctx, pki_base *pki,
				const QString &name, const QString &comment);
		/* object.delete (template.delete for templates), one entry
		 * per object, all in one transaction: either all objects are
		 * deleted or none, then one failure entry names the object
		 * that failed and memory is unchanged (BTD-130). The
		 * confirmation (question item.delete) and the deletion of a
		 * key or certificate on its token belong to the caller. The
		 * pointers in items are invalid after a successful call. */
		DeleteResult deleteItems(const ServiceContext &ctx,
				const QList<pki_base *> &items);
		static pki_base *fromIndex(const QModelIndex &index)
		{
			if (!index.isValid())
				return NULL;
			return static_cast<pki_base*>(index.internalPointer());
		}
		template <class T>
		static T *fromIndex(const QModelIndex &index)
		{
			return dynamic_cast<T*>(fromIndex(index));
		}
		void insertChild(pki_base *child, pki_base *parent = NULL);
		int rownumber(const pki_base *child) const;
		void createSuccess(const pki_base *pki) const;
		bool columnHidden(int col) const;
		virtual void saveHeaderState();
		void setVisualIndex(int i, int visualIndex);
		bool fixedHeaderSize(int sect);
		bool treeViewMode()
		{
			return treeview;
		}
		void colResizeStart()
		{
			colResizing++;
		}
		void colResizeEnd()
		{
			colResizing--;
		}
		dbheaderList getAllHeaders() {
			return allHeaders;
		}

		QMimeData *mimeData(const QModelIndexList &indexes) const;
		void emitDataChanged(pki_base *pki);
		bool containsType(enum pki_type t) const;
		void writeVcalendar(QIODevice &file, QStringList vcal) const;
		/* Item id of the current item of the view (setSelected()) */
		QVariant getSelected() const
		{
			return selected;
		}

	public slots:
		void columnResetDefaults();
		void sectionResized(int i, int, int newSize);
		void sortIndicatorChanged(int, Qt::SortOrder);
		void setSelected(const QVariant &v);
		void timerMaintenance();

	signals:
		void resetHeader() const;
		void updateHeader() const;
		void columnsContentChanged() const;
		void pkiChanged(pki_base *pki) const;
};

#endif
