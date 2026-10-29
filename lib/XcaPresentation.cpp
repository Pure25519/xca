/* vi: set sw=4 ts=4:
 *
 * Headless default of the presentation hook (BTD-36): no icon, no row
 * colour, no cursor.
 */

#include "XcaPresentation.h"

XcaPresentation_i *XcaPresentation::gui;

QVariant XcaPresentation::icon(const QString &name)
{
	return gui ? gui->icon(name) : QVariant();
}

QVariant XcaPresentation::background(XcaHighlight h)
{
	return gui ? gui->background(h) : QVariant();
}

void XcaPresentation::busy(bool start)
{
	if (gui)
		gui->busy(start);
}

void XcaPresentation::setGui(XcaPresentation_i *p)
{
	delete gui;
	gui = p;
}
