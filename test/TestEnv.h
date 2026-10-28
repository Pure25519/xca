/* vi: set sw=4 ts=4:
 *
 * Process-wide isolation of a test binary (BTD-28, BTD-83).
 */

#ifndef __TESTENV_H
#define __TESTENV_H

#include <QString>
#include <QTemporaryDir>

/* HOME and the XDG directories point into a temporary directory, so
 * settings.ini, dbhistory and .rnd never reach the real user profile and
 * test binaries running at the same time (ctest --parallel) do not share
 * them. With workInHome that directory is also the working directory, for
 * tests that create files with relative names. Removed with the object; destroy
 * it while Qt is still up (not as a static object). */
class TestEnv
{
	QTemporaryDir home;
	QString oldWorkDir;

  public:
	enum workDir { keepWorkDir, workInHome };
	explicit TestEnv(enum workDir w = keepWorkDir);
	~TestEnv();
};

#endif
