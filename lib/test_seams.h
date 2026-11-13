/* vi: set sw=4 ts=4:
 *
 * Test seams of xcacore (BTD-271): state that only tests set, compiled
 * only with BXC_PKI_TEST_SEAMS, which xcacore gets only in a build with
 * BUILD_TESTING. A build with BUILD_TESTING=OFF has none of it;
 * test_release_no_seams checks that with nm.
 *
 * The other seams of the same kind are static members of their class,
 * under the same definition: db_base::tokenDeleteHook and
 * tokenPrepareHook, db_token::tokenRenameHook and tokenRenamePrepareHook,
 * StagedFile::faultHook.
 */

#ifndef __TEST_SEAMS_H
#define __TEST_SEAMS_H

#ifdef BXC_PKI_TEST_SEAMS

namespace TestSeams
{
	/* DbTransaction (BTD-142): the nested commit after the next skip
	 * ones rolls back instead and reports success, like an inner
	 * helper that rolls back and returns without throwing; -1 clears
	 * a pending one */
	void injectNestedRollback(int skip = 0);
	bool injectionPending();
	/* Called by DbTransaction::commit() for a nested commit: true if
	 * this one rolls back */
	bool nestedCommitRollsBack();
	/* database_model (BTD-296): the next open throws errorEx right
	 * after the unlock and the schema check, outside their try block,
	 * as a later step of the constructor would */
	void failNextOpenAfterUnlock();
	/* Called by the database_model constructor: true once after
	 * failNextOpenAfterUnlock() */
	bool openFailsAfterUnlock();
}

#endif
#endif
