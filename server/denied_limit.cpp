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
	auto it = peers.find(peer);
	if (it != peers.end() && now - it->second.start >= window) {
		end(it->first, it->second, false, ended);
		peers.erase(it);
		it = peers.end();
	}
	if (it == peers.end()) {
		Window w;
		w.start = now;
		w.startUtc = nowUtc;
		it = peers.emplace(peer, w).first;
	}
	if (it->second.count >= perPeer) {
		it->second.suppressed++;
		return false;
	}
	it->second.count++;
	return true;
}

QList<DeniedLimit::Summary> DeniedLimit::expire(Clock::time_point now)
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

QList<DeniedLimit::Summary> DeniedLimit::drain()
{
	QList<Summary> ended;
	for (const auto &p : peers)
		end(p.first, p.second, false, &ended);
	peers.clear();
	return ended;
}

}
