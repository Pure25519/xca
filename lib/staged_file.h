/* vi: set sw=4 ts=4:
 *
 * Staged, atomic, owner-only file output (BTD-42; certstrap rules 7, 10
 * and 11 of bxc-pki PLAN.md 8.4). One helper for every file the command
 * line writes: keys, requests, certificates, CRLs, exports, trust lists.
 *
 *  stage():   the target directory is checked, a temporary file is
 *             created beside the target with O_EXCL (mode 0600 for a
 *             secret from its creation on; on Windows a protected DACL
 *             that grants OWNER RIGHTS only), written completely and
 *             fsync()ed. An existing target is refused (file_exists)
 *             unless replace is set. Nothing is visible under the
 *             target name yet.
 *  publish(): the temporary file becomes the target: without replace by
 *             link() (an existing target, also one that appeared since
 *             stage(), is never overwritten), with replace by rename();
 *             the directory is fsync()ed and the permissions of a secret
 *             are checked again (owner only, owned by this user).
 *  discard() and the destructor remove an unpublished temporary file.
 *
 * A run killed at any point leaves the target either absent or complete
 * (and an old target unchanged); at most a hidden temporary file
 * ".<name>.bxc-tmp-<random>" stays behind. Errors are serviceError
 * file_exists, invalid_output (no directory, not a regular file) and
 * write_failed, permission_check_failed with the system's reason.
 */

#ifndef __STAGED_FILE_H
#define __STAGED_FILE_H

#include <functional>

#include <QByteArray>
#include <QString>

class StagedFile
{
  public:
	/* The steps a test can make fail (faultHook) */
	enum step { create, write, sync, publish_step, recheck };

  private:
	QString targetPath{};
	QString tempPath{};
	bool secret{};
	bool replace{};
	bool staged{};
	bool published{};
	qint64 bytes{};

	void fault(enum step s) const;
	void removeTemp();

  public:
	StagedFile(const QString &target, bool secretFile, bool replaceTarget);
	~StagedFile();
	StagedFile(const StagedFile &) = delete;
	StagedFile &operator=(const StagedFile &) = delete;

	void stage(const QByteArray &data);
	void publish();
	void discard();

	QString target() const
	{
		return targetPath;
	}
	QString temporary() const
	{
		return tempPath;
	}
	bool isSecret() const
	{
		return secret;
	}
	bool isPublished() const
	{
		return published;
	}
	qint64 size() const
	{
		return bytes;
	}

	/* The checks of stage() without writing (--plan): the directory
	 * exists and is one, the target is absent (or replace and a
	 * regular file) */
	static void checkTarget(const QString &target, bool replaceTarget);
	/* stage() and publish() in one */
	static void writeFile(const QString &target, const QByteArray &data,
			bool secretFile, bool replaceTarget);

	/* Tests only (BTD-42 fault injection): called before each step
	 * with the target; a hook that returns true makes the step fail
	 * as if the system call had failed (EIO). A hook may also end the
	 * process to simulate a killed run. Never set in bxc-pki. */
	static std::function<bool(enum step, const QString &)> faultHook;
	static QString stepName(enum step s);
};

#endif
