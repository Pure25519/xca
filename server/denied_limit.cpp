/* vi: set sw=4 ts=4:
 *
 * The rate limit of auth.denied (BTD-155, BTD-314), see denied_limit.h.
 */

#include "denied_limit.h"

namespace xcaserver {

const std::chrono::seconds DeniedLimit::window(60);
const QString DeniedLimit::anyPeer("*");

void DeniedLimit::end(const QString &peer, const Window &w, bool total,
		QList<Summary> *ended)
{
	if (w.suppressed)
		*ended << Summary{ peer, w.startUtc, w.suppressed, total };
}

bool DeniedLimit::admit(const QString &peer, Clock::time_point now,
		const QString &nowUtc, QList<Summary> *ended)
{
	/* the total window first: its minute may have ended */
	if (allOpen && now - all.start >= window) {
		end(anyPeer, all, true, ended);
		allOpen = false;
	}
	if (!allOpen) {
		all = Window{ now, nowUtc, 0, 0 };
		allOpen = true;
	}

	auto it = peers.find(peer);
	if (it == peers.end() && full()) {
		/* the table is full: drop the windows that ended, else the
		 * peer shares the overflow window */
		ended->append(expirePeers(now));
		if (full())
			it = peers.find(anyPeer);
	}
	if (it != peers.end() && now - it->second.start >= window) {
		end(it->first, it->second, false, ended);
		peers.erase(it);
		it = peers.end();
	}
	if (it == peers.end()) {
		/* the overflow window is the one entry above peersMax */
		QString key = full() ? anyPeer : peer;
		it = peers.emplace(key, Window{ now, nowUtc, 0, 0 }).first;
	}
	if (it->second.count >= perPeer) {
		it->second.suppressed++;
		return false;
	}
	it->second.count++;
	if (all.count >= totalPerMinute) {
		all.suppressed++;
		return false;
	}
	all.count++;
	return true;
}

bool DeniedLimit::full() const
{
	/* the peer windows of the table, without the overflow window */
	return qint64(peers.size() - peers.count(anyPeer)) >= peersMax;
}

QList<DeniedLimit::Summary> DeniedLimit::expirePeers(Clock::time_point now)
{
	QList<Summary> ended;
	for (auto it = peers.begin(); it != peers.end();) {
		if (now - it->second.start < window) {
			++it;
			continue;
		}
		end(it->first, it->second, false, &ended);
		it = peers.erase(it);
	}
	return ended;
}

QList<DeniedLimit::Summary> DeniedLimit::expire(Clock::time_point now)
{
	QList<Summary> ended = expirePeers(now);
	if (allOpen && now - all.start >= window) {
		end(anyPeer, all, true, &ended);
		allOpen = false;
	}
	return ended;
}

QList<DeniedLimit::Summary> DeniedLimit::drain()
{
	QList<Summary> ended;
	for (const auto &p : peers)
		end(p.first, p.second, false, &ended);
	peers.clear();
	if (allOpen)
		end(anyPeer, all, true, &ended);
	allOpen = false;
	return ended;
}

}
