/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <stdio.h>
#include <string.h>

#include "base.h"
#include "XcaProgress.h"

/* The progress of the command line goes to stderr: stdout carries
 * only results (BTD-41) */
void XcaProgressCmd::stop()
{
	fputs(" finished.\n", stderr);
}

void XcaProgressCmd::start(const QString &what, int)
{
	fprintf(stderr, "\n%s\n", CCHAR(what));
}

void XcaProgressCmd::increment()
{
	static const char *spinner = "|/-\\";
	fprintf(stderr, "\rGenerating %c ...", spinner[i++%4]);
	fflush(stderr);
}

XcaProgress_i *XcaProgress::progress;

XcaProgress::XcaProgress(const QString &what, int max)
{
	if (!progress)
		progress = new XcaProgressCmd();
	progress->start(what, max);
}

XcaProgress::~XcaProgress()
{
	progress->stop();
}

void XcaProgress::increment()
{
	progress->increment();
}

void XcaProgress::setGui(XcaProgress_i *p)
{
	delete progress;
	progress = p;
}
