/* vi: set sw=4 ts=4:
 *
 * The audit log check of the GUI (BTD-103).
 */

#include "AuditVerify.h"
#include "XcaWarning.h"

#include "lib/exception.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

/* The fields of the report, in the order of the dialog: objectName
 * suffix (dlg_auditVerify_<key>), label */
static const QList<QPair<QString, const char *> > fields {
	{ "ok", QT_TRANSLATE_NOOP("AuditVerify", "Result") },
	{ "entries", QT_TRANSLATE_NOOP("AuditVerify", "Entries") },
	{ "firstBrokenSeq", QT_TRANSLATE_NOOP("AuditVerify",
		"First entry not anchored") },
	{ "reason", QT_TRANSLATE_NOOP("AuditVerify", "Reason") },
	{ "checkpoints", QT_TRANSLATE_NOOP("AuditVerify", "Valid checkpoints") },
	{ "lastCheckpointSeq", QT_TRANSLATE_NOOP("AuditVerify",
		"Last valid checkpoint") },
	{ "unanchoredEntries", QT_TRANSLATE_NOOP("AuditVerify",
		"Unanchored entries") },
	{ "auditKeys", QT_TRANSLATE_NOOP("AuditVerify", "Audit keys") },
	{ "adoptedEntries", QT_TRANSLATE_NOOP("AuditVerify",
		"Adopted entries") },
	{ "unauditedRevocations", QT_TRANSLATE_NOOP("AuditVerify",
		"Unaudited revocations") },
};

AuditVerify::AuditVerify(QWidget *parent) : QDialog(parent)
{
	setObjectName("dlg_auditVerify");
	setWindowTitle(tr("Verify audit log"));
	QVBoxLayout *layout = new QVBoxLayout(this);

	QFormLayout *form = new QFormLayout();
	for (const auto &f : fields) {
		QLabel *value = new QLabel(this);
		value->setObjectName("dlg_auditVerify_" + f.first);
		value->setTextInteractionFlags(Qt::TextSelectableByMouse);
		QLabel *label = new QLabel(tr(f.second), this);
		label->setBuddy(value);
		value->setAccessibleName(label->text());
		form->addRow(label, value);
		values[f.first] = value;
	}
	layout->addLayout(form);

	mismatches = new QTableWidget(0, 6, this);
	mismatches->setObjectName("dlg_auditVerify_mismatches");
	mismatches->setAccessibleName(tr("Revocation state mismatches"));
	mismatches->setHorizontalHeaderLabels({ tr("CA"), tr("Serial"),
		tr("Field"), tr("Expected"), tr("Actual"), tr("Entry") });
	mismatches->horizontalHeader()->setStretchLastSection(true);
	mismatches->setEditTriggers(QAbstractItemView::NoEditTriggers);
	layout->addWidget(mismatches);

	/* the trust anchor of BTD-101 */
	QFormLayout *pins = new QFormLayout();
	pinKeys = new QLineEdit(this);
	pinKeys->setObjectName("dlg_auditVerify_pinKeys");
	pinKeys->setAccessibleName(tr("Pinned audit key ids"));
	pinKeys->setPlaceholderText(tr("comma separated key ids"));
	pins->addRow(tr("Pinned audit key ids"), pinKeys);
	minCheckpoint = new QLineEdit(this);
	minCheckpoint->setObjectName("dlg_auditVerify_minCheckpoint");
	minCheckpoint->setAccessibleName(tr("Minimum checkpoint"));
	pins->addRow(tr("Minimum checkpoint"), minCheckpoint);
	layout->addLayout(pins);

	QDialogButtonBox *buttons = new QDialogButtonBox(this);
	QPushButton *verifyButton = buttons->addButton(tr("Verify"),
					QDialogButtonBox::ActionRole);
	verifyButton->setObjectName("btn_verify");
	adoptButton = buttons->addButton(tr("Adopt unanchored entries"),
					QDialogButtonBox::ActionRole);
	adoptButton->setObjectName("btn_adopt");
	QPushButton *close = buttons->addButton(QDialogButtonBox::Close);
	close->setObjectName("btn_close");
	layout->addWidget(buttons);
	connect(verifyButton, SIGNAL(clicked()), this, SLOT(verify()));
	connect(adoptButton, SIGNAL(clicked()), this, SLOT(adopt()));
	connect(buttons, SIGNAL(rejected()), this, SLOT(reject()));

	resize(640, 520);
	verify();
}

bool AuditVerify::adoptionOffered() const
{
	return result.reason == "checkpoint_missing" &&
		result.auditKeys.isEmpty();
}

static QString seqText(qint64 seq)
{
	return seq ? QString::number(seq) : QObject::tr("none");
}

void AuditVerify::show(const AuditVerifyResult &r)
{
	result = r;
	values["ok"]->setText(r.ok() ? tr("OK") : tr("Failed"));
	values["entries"]->setText(QString::number(r.entries));
	values["firstBrokenSeq"]->setText(seqText(r.firstBrokenSeq));
	values["reason"]->setText(r.reason.isEmpty() ? tr("none") : r.reason);
	values["checkpoints"]->setText(QString::number(r.checkpoints));
	values["lastCheckpointSeq"]->setText(seqText(r.lastCheckpointSeq));
	values["unanchoredEntries"]->setText(
		QString::number(r.unanchoredEntries));
	values["auditKeys"]->setText(r.auditKeys.isEmpty() ? tr("none") :
		r.auditKeys.join("\n"));
	values["adoptedEntries"]->setText(QString::number(r.adoptedEntries));
	values["unauditedRevocations"]->setText(
		QString::number(r.unauditedRevocations));

	mismatches->setRowCount(r.mismatches.size());
	for (int i = 0; i < r.mismatches.size(); i++) {
		const AuditStateMismatch &m = r.mismatches[i];
		QStringList cells { QString::number(m.caId), m.serial, m.field,
			m.expected, m.actual, seqText(m.seq) };
		for (int c = 0; c < cells.size(); c++)
			mismatches->setItem(i, c, new QTableWidgetItem(cells[c]));
	}
	adoptButton->setVisible(adoptionOffered());
}

void AuditVerify::verify()
{
	AuditVerifyPins pins;
	pins.keys = pinKeys->text().split(',', Qt::SkipEmptyParts);
	for (QString &k : pins.keys)
		k = k.trimmed();
	pins.minCheckpoint = minCheckpoint->text().trimmed().toLongLong();
	try {
		show(AuditLog::verify(pins));
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void AuditVerify::adopt()
{
	if (!adoptionOffered())
		return;
	/* The same decision as xca --audit-adopt (BTD-110): the first key
	 * takes over entries nobody signed */
	ServiceContext ctx = ServiceContext::localUser(ServiceContext::gui);
	if (!xcaWarning::confirm(ctx, "audit.adopt", tr("Sign the %1 audit "
		"entries that no checkpoint covers with a new audit key? "
		"Check the log first: the adoption is recorded and cannot be "
		"undone, and it also signs entries that may have been changed.")
		.arg(result.unanchoredEntries)))
		return;
	try {
		AuditLog::adoptUnanchored(ctx);
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
	verify();
}
