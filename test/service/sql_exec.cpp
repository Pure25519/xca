/* vi: set sw=4 ts=4:
 *
 * Test helper for the CLI tests (BTD-117): what sqlite3 does, without a
 * dependency on the sqlite3 program. Prepares databases that the xca
 * command line cannot create (e.g. one with an empty password) and reads
 * what xca left in a database.
 *
 * sql_exec <database> (<dump.sql> | -c <statement> | --sleep <seconds>)...
 *
 * A dump is a file of statements, each ending with ';' at a line end
 * (Python's sqlite3 iterdump(), like data/schema8-fork.sql). The rows of
 * every -c statement are printed, one per line, columns joined by '|'.
 * --sleep waits, so that a lock taken before (-c 'BEGIN EXCLUSIVE') is
 * held for that long and given back at the exit (BTD-214).
 * Exit code 1 on the first failing statement.
 */

#include <QCoreApplication>
#include <QFile>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QStringList>
#include <QTextStream>
#include <QThread>

static bool run(QSqlDatabase &db, const QString &statement, bool print)
{
	QSqlQuery q(db);
	if (!q.exec(statement)) {
		QTextStream(stderr) << statement << ": "
				<< q.lastError().text() << "\n";
		return false;
	}
	QTextStream out(stdout);
	while (print && q.next()) {
		QStringList cols;
		for (int i = 0; i < q.record().count(); i++)
			cols << q.value(i).toString();
		out << cols.join("|") << "\n";
	}
	return true;
}

int main(int argc, char *argv[])
{
	QCoreApplication app(argc, argv);
	QStringList args = app.arguments().mid(1);

	if (args.size() < 2) {
		QTextStream(stderr) << "usage: sql_exec <database> "
				"(<dump.sql> | -c <statement> | "
				"--sleep <seconds>)...\n";
		return 1;
	}
	QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
	db.setDatabaseName(args.takeFirst());
	if (!db.open()) {
		QTextStream(stderr) << db.lastError().text() << "\n";
		return 1;
	}
	while (!args.isEmpty()) {
		QString arg = args.takeFirst();
		if (arg == "-c") {
			if (args.isEmpty() || !run(db, args.takeFirst(), true))
				return 1;
			continue;
		}
		if (arg == "--sleep") {
			if (args.isEmpty())
				return 1;
			QThread::sleep(args.takeFirst().toULong());
			continue;
		}
		QFile dump(arg);
		if (!dump.open(QIODevice::ReadOnly)) {
			QTextStream(stderr) << arg << ": "
					<< dump.errorString() << "\n";
			return 1;
		}
		QString statement;
		while (!dump.atEnd()) {
			statement += QString::fromUtf8(dump.readLine());
			if (!statement.trimmed().endsWith(';'))
				continue;
			if (!run(db, statement, false))
				return 1;
			statement.clear();
		}
	}
	db.close();
	return 0;
}
