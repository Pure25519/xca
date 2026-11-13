/* vi: set sw=4 ts=4:
 *
 * Test seams of xcacore (BTD-271), see test_seams.h
 */

#include "test_seams.h"

#ifdef BXC_PKI_TEST_SEAMS

static int nestedRollback;

void TestSeams::injectNestedRollback(int skip)
{
	nestedRollback = skip + 1;
}

bool TestSeams::injectionPending()
{
	return nestedRollback > 0;
}

bool TestSeams::nestedCommitRollsBack()
{
	return nestedRollback > 0 && --nestedRollback == 0;
}

#endif
