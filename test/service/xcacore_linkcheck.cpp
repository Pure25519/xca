/* vi: set sw=4 ts=4:
 *
 * Links every object of xcacore (whole archive) with Qt Core and Qt Sql
 * only (BTD-36): a GUI symbol left in any core object fails the link,
 * not only in the objects a test happens to use. Running it opens and
 * closes nothing; test_core_link checks its NEEDED entries.
 */

#include <QCoreApplication>

#include "lib/func_base.h"

int main(int argc, char *argv[])
{
	QCoreApplication app(argc, argv);
	return IS_GUI_APP ? 1 : 0;
}
