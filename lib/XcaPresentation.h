/* vi: set sw=4 ts=4:
 *
 * What the core asks the GUI to show (BTD-36): item icons, row colours
 * and the wait cursor around PKCS#11 calls. The core links Qt Core only,
 * so the GUI implementation (XcaPresentationGui) provides the
 * pixmaps, brushes and cursor. Without it (xca --no-gui, the service
 * tests) the models carry no decoration and the cursor stays.
 */

#ifndef __XCAPRESENTATION_H
#define __XCAPRESENTATION_H

#include <QString>
#include <QVariant>

/* Row colours of the item models (Qt::BackgroundRole) */
enum class XcaHighlight { red, yellow, cyan };

class XcaPresentation_i
{
  public:
	/* The icon of the resource name, e.g. ":keyIco"; an empty name is
	 * the blank placeholder of the same size */
	virtual QVariant icon(const QString &name) = 0;
	virtual QVariant background(XcaHighlight h) = 0;
	virtual void busy(bool start) = 0;
	virtual ~XcaPresentation_i() = default;
};

class XcaPresentation
{
  private:
	static XcaPresentation_i *gui;

  public:
	static QVariant icon(const QString &name);
	static QVariant background(XcaHighlight h);
	static void busy(bool start);
	/* Takes ownership; nullptr returns to the headless default */
	static void setGui(XcaPresentation_i *p);
};
#endif
