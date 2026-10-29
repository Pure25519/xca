/* vi: set sw=4 ts=4:
 *
 * GUI side of the presentation hook (BTD-36): the pixmaps, row colours
 * and wait cursor that lib/ used to create itself. The colours follow
 * the palette (light or dark), set up again on a palette change.
 */

#ifndef __XCAPRESENTATIONGUI_H
#define __XCAPRESENTATIONGUI_H

#include "lib/XcaPresentation.h"

#include <QApplication>
#include <QBrush>
#include <QColor>
#include <QCursor>
#include <QDebug>
#include <QPalette>
#include <QPixmap>

class XcaPresentationGui : public XcaPresentation_i
{
  private:
	static inline QBrush red, yellow, cyan;

  public:
	static void setupColors(const QPalette &pal)
	{
		int factor = 50;
		if (pal.window().color().value() > pal.windowText().color().value())
			factor = 125;

		qDebug() << "WindowColor" << pal.window().color().value()
				 << "TextColor" << pal.windowText().color().value()
				 << "Factor" << factor;
		red = QBrush(QColor(255, 0, 0).lighter(factor));
		yellow = QBrush(QColor(255, 255, 0).lighter(factor));
		cyan = QBrush(QColor(127, 255, 212).lighter(factor));
	}
	QVariant icon(const QString &name) override
	{
		if (name.isEmpty()) {
			QPixmap p(QSize(20, 20));
			p.fill(Qt::transparent);
			return QVariant(p);
		}
		return QVariant(QPixmap(name));
	}
	QVariant background(XcaHighlight h) override
	{
		switch (h) {
		case XcaHighlight::red:
			return QVariant(red);
		case XcaHighlight::yellow:
			return QVariant(yellow);
		case XcaHighlight::cyan:
			return QVariant(cyan);
		}
		return QVariant();
	}
	void busy(bool start) override
	{
		if (start)
			QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
		else
			QApplication::restoreOverrideCursor();
	}
};
#endif
