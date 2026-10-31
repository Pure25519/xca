/* vi: set sw=4 ts=4:
 *
 * The audit log check of the GUI (BTD-103, PLAN.md 6.3): runs the same
 * AuditLog::verify() as xca --audit-verify and shows its report, takes
 * the pins of BTD-101 and offers the adoption of BTD-110 when verify
 * reports an unsigned log without key.
 */

#ifndef __AUDITVERIFY_H
#define __AUDITVERIFY_H

#include <QDialog>
#include <QMap>

#include "lib/audit.h"

class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

class AuditVerify: public QDialog
{
	Q_OBJECT

	QMap<QString, QLabel *> values{};
	QTableWidget *mismatches{};
	QLineEdit *pinKeys{}, *minCheckpoint{};
	QPushButton *adoptButton{};
	AuditVerifyResult result{};

	void display(const AuditVerifyResult &r);

  public:
	AuditVerify(QWidget *parent);
	/* The report shown, as --audit-verify prints it */
	const AuditVerifyResult &report() const
	{
		return result;
	}
	/* Adoption is offered: no audit key yet and checkpoint_missing */
	bool adoptionOffered() const;

  public slots:
	void verify();
	void adopt();
};
#endif
