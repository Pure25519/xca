/* vi: set sw=4 ts=4:
 *
 * Staged, atomic, owner-only file output (BTD-42; certstrap rules 7, 10
 * and 11 of bxc-pki PLAN.md 8.4). One helper for every file the command
 * line writes: keys, requests, certificates, CRLs, exports, trust lists.
 *
 *  stage():   the target directory is checked, a temporary file is
 *             created beside the target with O_EXCL (mode 0600 for a
 *             secret from its creation on; on Windows a protected DACL
 *             that grants OWNER RIGHTS only), checked to be owner-only
 *             (a file system that ignores the mode is refused here,
 *             before the database commit), written completely and
 *             fsync()ed. An existing target is refused (file_exists)
 *             unless replace is set. Nothing is visible under the
 *             target name yet.
 *  publish(): the temporary file becomes the target: without replace by
 *             link() (an existing target, also one that appeared since
 *             stage(), is never overwritten), with replace by rename();
 *             the directory is fsync()ed and the permissions of a secret
 *             are checked again (owner only, owned by this user); a
 *             file that fails the check is removed again.
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
#include <QStringList>

class StagedFile
{
  public:
	/* The steps a test can make fail (faultHook) */
	enum step { create, write, sync, publish_step, recheck, owner_check,
		swap };

  private:
	QString targetPath{};
	QString tempPath{};
	bool secret{};
	bool replace{};
	bool staged{};
	bool published{};
	qint64 bytes{};

	bool injected(enum step s) const;
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

/* A directory written as a whole (trust lists, review of xca#62): its
 * files are staged in a hidden sibling ".<name>.bxc-tmp-<random>", and
 * publish() swaps the sibling with the target in one rename (Linux:
 * renameat2() RENAME_EXCHANGE; elsewhere, or on a file system without
 * it, two renames). A reader of the directory sees the old or the new
 * content, never a mix; files of an earlier export do not stay behind.
 *
 * The target is an existing directory, not a mount point. It is empty,
 * or it holds exactly an earlier export: its manifest (marker, e.g.
 * "manifest.json") parses as a JSON object whose "schema" is schema, and
 * every entry below the target is the marker, a file the manifest lists
 * under entries[].path, or a directory above one of them. An earlier
 * export is replaced only with replace (file_exists); any other content
 * is refused (invalid_output) and not touched. A manifest of something
 * else with the same name (web apps, npm) is no earlier export.
 *
 * publish() checks the target again right before the swap, after the
 * database commit, and removes from the old content only the entries of
 * that check; anything that appeared later stays in the old content,
 * which then stays under its temporary name (leftover()). */
class StagedDirectory
{
	QString givenPath{};     // absolute, as given
	QString targetPath{};    // canonical (symbolic links resolved)
	QString tempPath{};
	QString marker{}, schema{};
	QString leftoverPath{};
	bool replace{};
	bool staged{};
	bool published{};

	void removeTemp();

  public:
	StagedDirectory(const QString &target, const QString &markerName,
			const QString &markerSchema, bool replaceTarget);
	~StagedDirectory();
	StagedDirectory(const StagedDirectory &) = delete;
	StagedDirectory &operator=(const StagedDirectory &) = delete;

	/* The checks of stage() without writing (--plan); the entries of
	 * the earlier export, relative to target (empty: an empty target) */
	static QStringList checkTarget(const QString &target,
			const QString &markerName, const QString &markerSchema,
			bool replaceTarget);
	/* The checks, then the empty sibling */
	void stage();
	/* path below the target: the same path in the sibling; else "" */
	QString stagedPath(const QString &path) const;
	bool contains(const QString &path) const;
	/* After the files below it are published into the sibling */
	void publish();
	void discard();

	bool isPublished() const
	{
		return published;
	}
	/* The old content that could not be removed completely after the
	 * swap (files that appeared after the check); empty if none */
	QString leftover() const
	{
		return leftoverPath;
	}
};

#endif
