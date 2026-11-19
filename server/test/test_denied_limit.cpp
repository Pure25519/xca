/* vi: set sw=4 ts=4:
 *
 * The rate limit of auth.denied (BTD-314) with simulated peers and clock:
 * the peer table stays at its bound, the single entries per minute stay at
 * the total cap, and every refusal is either a single entry or counted in a
 * summary.
 */

#include <QTest>

#include "denied_limit.h"

using xcaserver::DeniedLimit;

class test_denied_limit: public QObject
{
	Q_OBJECT

	DeniedLimit::Clock::time_point t0{ DeniedLimit::Clock::now() };

	static qint64 suppressed(const QList<DeniedLimit::Summary> &l)
	{
		qint64 n = 0;
		for (const DeniedLimit::Summary &s : l)
			n += s.suppressed;
		return n;
	}

  private slots:
	void perPeer();
	void tableBound();
	void totalCap();
	void manyPeersOneMinute();
	void drain();
};

/* the limit of BTD-155: perPeer single entries per peer and minute */
void test_denied_limit::perPeer()
{
	DeniedLimit l(2, 10, 1000);
	QList<DeniedLimit::Summary> ended;
	QVERIFY(l.admit("10.0.0.1", t0, "t0", &ended));
	QVERIFY(l.admit("10.0.0.1", t0, "t0", &ended));
	QVERIFY(!l.admit("10.0.0.1", t0, "t0", &ended));
	QVERIFY(l.admit("10.0.0.2", t0, "t0", &ended));
	QVERIFY(ended.isEmpty());
	/* a new minute of the peer: its summary, then single entries again */
	QVERIFY(l.admit("10.0.0.1", t0 + DeniedLimit::window, "t1", &ended));
	QCOMPARE(ended.size(), 1);
	QCOMPARE(ended[0].peer, QString("10.0.0.1"));
	QCOMPARE(ended[0].suppressed, qint64(1));
	QCOMPARE(ended[0].startUtc, QString("t0"));
	QVERIFY(!ended[0].total);
}

/* more peers than the bound: the table keeps peersMax windows plus the one
 * overflow window "*", which the further peers share */
void test_denied_limit::tableBound()
{
	DeniedLimit l(1, 3, 1000);
	QList<DeniedLimit::Summary> ended;
	int single = 0;
	for (int i = 0; i < 100; i++)
		single += l.admit(QString("10.0.1.%1").arg(i), t0, "t0", &ended);
	QCOMPARE(l.windows(), 4);
	/* three peers of the table and one entry of the overflow window */
	QCOMPARE(single, 4);
	QList<DeniedLimit::Summary> s = l.expire(t0 + DeniedLimit::window);
	QCOMPARE(s.size(), 1);
	QCOMPARE(s[0].peer, DeniedLimit::anyPeer);
	QCOMPARE(s[0].suppressed, qint64(96));
	QCOMPARE(l.windows(), 0);
}

/* one peer, the total cap below its own limit */
void test_denied_limit::totalCap()
{
	DeniedLimit l(10, 10, 2);
	QList<DeniedLimit::Summary> ended;
	int single = 0;
	for (int i = 0; i < 5; i++)
		single += l.admit("10.0.2.1", t0, "t0", &ended);
	QCOMPARE(single, 2);
	QList<DeniedLimit::Summary> s = l.expire(t0 + DeniedLimit::window);
	QCOMPARE(s.size(), 1);
	QVERIFY(s[0].total);
	QCOMPARE(s[0].peer, DeniedLimit::anyPeer);
	QCOMPARE(s[0].suppressed, qint64(3));
	/* the next minute has the full cap again */
	QVERIFY(l.admit("10.0.2.1", t0 + DeniedLimit::window, "t1", &ended));
}

/* the case of the ticket: many addresses within one minute */
void test_denied_limit::manyPeersOneMinute()
{
	const qint64 perPeer = 5, peersMax = 64, total = 100;
	DeniedLimit l(perPeer, peersMax, total);
	QList<DeniedLimit::Summary> ended;
	qint64 single = 0, refusals = 0;
	for (int i = 0; i < 10000; i++) {
		QString peer = QString("2001:db8::%1").arg(i, 0, 16);
		for (int j = 0; j < 3; j++) {
			auto now = t0 + std::chrono::milliseconds(i);
			single += l.admit(peer, now, "t0", &ended);
			refusals++;
		}
		QVERIFY(l.windows() <= int(peersMax) + 1);
	}
	QVERIFY(ended.isEmpty());
	QCOMPARE(single, total);
	ended = l.expire(t0 + DeniedLimit::window + std::chrono::seconds(10));
	QCOMPARE(single + suppressed(ended), refusals);
	QCOMPARE(l.windows(), 0);
}

/* the stop writes every summary */
void test_denied_limit::drain()
{
	DeniedLimit l(1, 1, 1);
	QList<DeniedLimit::Summary> ended;
	QVERIFY(l.admit("10.0.3.1", t0, "t0", &ended));
	QVERIFY(!l.admit("10.0.3.1", t0, "t0", &ended));
	QVERIFY(!l.admit("10.0.3.2", t0, "t0", &ended));
	QList<DeniedLimit::Summary> s = l.drain();
	QCOMPARE(suppressed(s), qint64(2));
	QCOMPARE(l.windows(), 0);
	QVERIFY(l.drain().isEmpty());
}

QTEST_GUILESS_MAIN(test_denied_limit)
#include "test_denied_limit.moc"
