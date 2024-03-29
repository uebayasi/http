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
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include "http.h"

static int	 http_response(FILE *, struct http_hdrs *);

static FILE	*http_fp;

int
http_connect(struct url *url, struct url *proxy)
{
	const char	*host, *port;
	int		 s;

	if (url->port[0] == '\0')
		(void)strlcpy(url->port, "80", sizeof(url->port));

	host = proxy ? proxy->host : url->host;
	port = proxy ? proxy->port : url->port;
	if ((s = tcp_connect(host, port)) == -1)
		return -1;

	if ((http_fp = fdopen(s, "r+")) == NULL)
		err(1, "%s: fdopen", __func__);

	if (proxy && proxy_connect(http_fp, url, proxy) == -1)
		return -1;

	return s;
}

int
proxy_connect(FILE *fp, struct url *url, struct url *proxy)
{
	int	code;

	send_cmd(fp,
	    "CONNECT %s:%s HTTP/1.0\r\n"
	    "Host: %s\r\n"
	    "User-Agent: %s\r\n"
	    "%s%s",
	    url->host,
	    url->port,
	    url->host,
	    ua,
	    url->basic_auth[0] ? "Proxy-Authorization: Basic " : "",
	    url->basic_auth[0] ? url->basic_auth : "");
	code = http_response(fp, NULL);
	if (code != 200)
		errx(1, "Error retrieving file: %s", http_errstr(code));

	return 0;
}

int
http_get(const char *fn, off_t offset, struct url *url, struct http_hdrs *hdrs)
{
	char	range[BUFSIZ];
	int	res;

	(void)snprintf(range, sizeof(range), "Range: bytes=%lld-\r\n", offset);
	send_cmd(http_fp,
	    "GET %s HTTP/1.0\r\n"
	    "Host: %s\r\n"
	    "User-Agent: %s\r\n"
	    "%s"
	    "%s%s",
	    url->path ? url->path : "/",
	    url->host,
	    ua,
	    offset ? range : "",
	    url->basic_auth[0] ? "Authorization: Basic " : "",
	    url->basic_auth[0] ? url->basic_auth : "");
	res = http_response(http_fp, hdrs);
	if (res != 200 && res != 206)
		goto err;

	/* Expected a partial content but got full content */
	if (offset && (res == 200)) {
		offset = 0;
		if (truncate(fn, 0) == -1)
			err(1, "%s: truncate", __func__);
	}

	retr_file(http_fp, fn, hdrs->c_len + offset, offset);
err:
	fclose(http_fp);
	return res;
}

static int
http_response(FILE *fp, struct http_hdrs *hdrs)
{
	char		*buf;
	size_t		 len;
	int		 res;

	buf = http_parseln(fp, NULL);
	if (ftp_debug)
		fprintf(stderr, "<<< %s\n", buf);

	res = http_response_code(buf);
	free(buf);
	while ((buf = http_parseln(fp, &len))) {
		if (len == 0)
			break;	/* end of headers */

		if (hdrs && header_insert(hdrs, buf) != 0)
			return -1;

		free(buf);
	}

	return res;
}

char *
http_parseln(FILE *fp, size_t *lenp)
{
	char	*buf;
	size_t	 len;

	if ((buf = fparseln(fp, &len, NULL, "\0\0\0", 0)) == NULL)
		err(1, "%s", __func__);

	if (len > 0 && buf[len - 1] == '\r')
		buf[--len] = '\0';

	if (lenp)
		*lenp = len;

	return buf;
}

