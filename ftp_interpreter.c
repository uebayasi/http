/*
 * Copyright (c) 2015 Sunil Nimmagadda <sunil@nimmagadda.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <err.h>
#include <histedit.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE	*ctrl_fp;

static char	*ftp_prompt(void);

void
ftp_command(FILE *fp)
{
	HistEvent	 hev;
	EditLine	*el;
	History		*hist;
	const char	*buf;
	int		 len;

	ctrl_fp = fp;
	if ((el = el_init(getprogname(), stdin, stdout, stderr)) == NULL)
		errx(1, "%s: el_init failed", __func__);

	if ((hist = history_init()) == NULL)
		errx(1, "%s: history_init failed", __func__);

	history(hist, &hev, H_SETSIZE, 100);
	el_set(el, EL_HIST, history, hist);
	el_set(el, EL_EDITOR, "emacs");
	el_set(el, EL_PROMPT, ftp_prompt);
	el_source(el, NULL);
	while (1) {
		if ((buf = el_gets(el, &len)) == NULL || len == 0)
			break;

		if (strlen(buf) > 1)
			history(hist, &hev, H_ENTER, buf);
	}

	history_end(hist);
	el_end(el);
	exit(0);
}

static char *
ftp_prompt(void)
{
	return ("ftp> ");
}
