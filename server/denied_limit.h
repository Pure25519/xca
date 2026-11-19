/* vi: set sw=4 ts=4:
 *
 * The rate limit of auth.denied (BTD-155, BTD-314): which refusal gets an
 * entry of its own and which is only counted for a summary entry.
 *
 * Per peer address at most perPeer single entries per minute (a window
 * starts with the first refusal of the peer). The table holds at most
 * peersMax peer windows; the refusals of further peers share one overflow
 * window with the peer "*". Over all peers at most totalPerMinute single
 * entries per minute; what the total cap holds back is counted in a window
 * of its own (Summary::total). A window that ended with refusals left out
 * gives one Summary.
 *
 * No clock and no database of its own: the caller passes the time and
 * writes the entries (AuthAudit). Not thread-safe; AuthAudit holds its
 * mutex around every call.
 */

#ifndef __XCA_SERVER_DENIED_LIMIT_H
#define __XCA_SERVER_DENIED_LIMIT_H

#include <chrono>
#include <map>

#include <QList>
#include <QString>

namespace xcaserver {

class DeniedLimit
{
  public:
	using Clock = std::chrono::steady_clock;
	static const std::chrono::seconds window;
	/* the peer of the overflow window and of the total window */
	static const QString anyPeer;

	/* The refusals left out of one window */
	class Summary
	{
	  public:
		QString peer{};
		/* ISO 8601 UTC of the window start */
		QString startUtc{};
		qint64 suppressed{};
		/* held back by the total cap, not by the peer's limit */
		bool total{};
	};

	DeniedLimit(qint64 perPeer, qint64 peersMax, qint64 totalPerMinute)
		: perPeer(perPeer), peersMax(peersMax),
		  totalPerMinute(totalPerMinute)
	{
	}
	/* One refusal of peer at now (nowUtc: the same time as text, for a
	 * new window). true: it gets an entry of its own. The summaries of
	 * the windows that ended are appended to ended. */
	bool admit(const QString &peer, Clock::time_point now,
			const QString &nowUtc, QList<Summary> *ended);
	/* The summaries of the windows that ended before now */
	QList<Summary> expire(Clock::time_point now);
	/* The summaries of all windows; the table is empty afterwards */
	QList<Summary> drain();
	/* Peer windows in the table, the overflow window included */
	int windows() const
	{
		return int(peers.size());
	}

	const qint64 perPeer;
	const qint64 peersMax;
	const qint64 totalPerMinute;

  private:
	class Window
	{
	  public:
		Clock::time_point start{};
		QString startUtc{};
		qint64 count{};
		qint64 suppressed{};
	};
	std::map<QString, Window> peers{};
	Window all{};
	bool allOpen{};

	static void end(const QString &peer, const Window &w, bool total,
			QList<Summary> *ended);
	/* peersMax peer windows (the overflow window not counted) */
	bool full() const;
	QList<Summary> expirePeers(Clock::time_point now);
};

}

#endif
