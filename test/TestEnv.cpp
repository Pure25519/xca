/* vi: set sw=4 ts=4:
 *
 * Process-wide isolation of a test binary (BTD-28, BTD-83).
 */

#include <QDir>
#include <QtGlobal>

#include "TestEnv.h"

TestEnv::TestEnv(enum workDir w)
	: home(QDir::tempPath() + "/xca-test-home-XXXXXX")
{
	static const char * const xdg[][2] = {
		{ "XDG_CONFIG_HOME", "/.config" },
		{ "XDG_DATA_HOME", "/.local/share" },
		{ "XDG_CACHE_HOME", "/.cache" },
		{ "XDG_STATE_HOME", "/.local/state" },
	};
	if (!home.isValid())
		qFatal("Cannot create the temporary HOME of the tests");

	qputenv("HOME", home.path().toLocal8Bit());
	for (auto &x : xdg) {
		QString dir = home.path() + x[1];
		QDir().mkpath(dir);
		qputenv(x[0], dir.toLocal8Bit());
	}
	if (w == workInHome) {
		oldWorkDir = QDir::currentPath();
		if (!QDir::setCurrent(home.path()))
			qFatal("Cannot change into the temporary HOME of the tests");
	}
}

TestEnv::~TestEnv()
{
	/* Leave the directory before it is removed */
	if (!oldWorkDir.isEmpty())
		QDir::setCurrent(oldWorkDir);
}
