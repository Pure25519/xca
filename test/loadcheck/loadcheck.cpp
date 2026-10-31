/* vi: set sw=4 ts=4:
 *
 * Test-only preload library (BTD-251). Put in front of a binary with
 * LD_PRELOAD, it writes the path of every object loaded in the process to
 * the file named by XCA_LOADCHECK_OUT when the process exits: after every
 * plugin and lazily loaded library, so test/loadcheck/one_libcrypto.cmake
 * sees what a run really had in memory. Never installed, never linked into
 * a product binary.
 */

#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int writeObject(struct dl_phdr_info *info, size_t, void *data)
{
	if (info->dlpi_name && info->dlpi_name[0])
		fprintf(static_cast<FILE *>(data), "%s\n", info->dlpi_name);
	return 0;
}

__attribute__((destructor)) static void writeLoadedObjects()
{
	const char *path = getenv("XCA_LOADCHECK_OUT");
	if (!path)
		return;
	FILE *f = fopen(path, "w");
	if (!f)
		return;
	fprintf(f, "# pid %d\n", static_cast<int>(getpid()));
	dl_iterate_phdr(writeObject, f);
	fclose(f);
}
