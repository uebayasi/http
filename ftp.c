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

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "http.h"

int	ftp_connect(struct url *, struct url *);
int	ftp_retr(struct url *, const char *,int, struct headers *);

struct proto proto_ftp = {
	ftp_connect,
	ftp_retr
};

static int	ctrl_sock = -1;

int ftp_auth(struct url *url)
{
	return (-1);
}

int
ftp_connect(struct url *url, struct url *proxy)
{
	if (url->port[0] == '\0')
		(void)strlcpy(url->port, "21", sizeof(url->port));

	if ((ctrl_sock = tcp_connect(url->host, url->port)) == -1)
		return (-1);

	return (ctrl_sock);
}

int
ftp_retr(struct url *url, const char *fn, int resume, struct headers *hdrs)
{
	return (-1);
}
