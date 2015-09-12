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

#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include "http.h"

void	 http_init(void);
int	 http_parse_headers(FILE *, struct headers *);
char	*http_response(FILE *, size_t *);
int	 proxy_connect(int, struct url *, struct url *);

extern const char	*ua;
static int		 s = -1;

int
http_connect(struct url *url, struct url *proxy)
{
	const char	*host, *port;

	if (url->port[0] == '\0')
		(void)strlcpy(url->port, "www", sizeof(url->port));

	host = (proxy) ? proxy->host : url->host;
	port = (proxy) ? proxy->port : url->port;

	if ((s = tcp_connect(host, port)) == -1)
		return (-1);

	if (proxy && proxy_connect(s, url, proxy) == -1)
		return (-1);

	return (s);
}

int
proxy_connect(int sock, struct url *url, struct url *proxy)
{
	FILE		*fp;
	const char	*proxy_auth = NULL;
	int		 code;

	if ((fp = fdopen(sock, "r+")) == NULL)
		err(1, "%s: fdopen", __func__);

	if (proxy->user[0] || proxy->pass[0])
		proxy_auth = base64_encode(proxy->user, proxy->pass);

	fprintf(fp,
	    "CONNECT %s:%s HTTP/1.0\r\n"
	    "Host: %s\r\n"
	    "User-Agent: %s\r\n"
	    "%s%s"
	    "\r\n",
	    url->host,
	    url->port,
	    url->host,
	    ua,
	    (proxy_auth) ? "Proxy-Authorization: Basic " : "",
	    (proxy_auth) ? proxy_auth : "");

	fflush(fp);
	code = http_response_code(fp);
	if (code != 200)
		errx(1, "Error retrieving file: %s", http_errstr(code));

	return (0);
}

int
http_get(struct url *url, const char *out_fn, int resume, struct headers *hdrs)
{
	struct stat	 sb;
	char		 range[BUFSIZ];
	off_t		 offset;
	const char	*basic_auth = NULL;
	FILE		*fin;
	int		 flags, res = -1;

	if ((fin = fdopen(s, "r+")) == NULL)
		err(1, "%s: fdopen", __func__);

	offset = 0;
	if (resume) {
		if (stat(out_fn, &sb) == 0) {
			offset = sb.st_size;
			snprintf(range, sizeof(range),
			    "Range: bytes=%lld-\r\n", sb.st_size);
		} else
			resume = 0;
	}

	if (url->user[0] || url->pass[0])
		basic_auth = base64_encode(url->user, url->pass);

	fprintf(fin,
	    "GET %s HTTP/1.0\r\n"
	    "Host: %s\r\n"
	    "User-Agent: %s\r\n"
	    "%s"
	    "%s%s"
	    "\r\n",
	    (url->path[0]) ? url->path : "/",
	    url->host,
	    ua,
	    (resume) ? range : "",
	    (basic_auth) ? "Authorization: Basic " : "",
	    (basic_auth) ? basic_auth : "");

	fflush(fin);
	if ((res = http_response_code(fin)) == -1)
		goto err;

	if (http_parse_headers(fin, hdrs) != 0) {
		res = -1;
		goto err;
	}

	flags = O_CREAT | O_WRONLY;
	if (resume && (res == 206))
		flags |= O_APPEND;
	else {
		flags |= O_TRUNC;
		offset = 0;
	}

	switch (res) {
	case 206:	/* Partial content */
	case 200:	/* OK */
		retr_file(fin, out_fn, flags, hdrs->c_len + offset, offset);
		break;
	}

err:
	fclose(fin);
	return (res);
}

int
http_parse_headers(FILE *fin, struct headers *hdrs)
{
	char		*buf;
	size_t		 len;
	int		 ret = -1;

	while ((buf = http_response(fin, &len))) {
		if (len == 0)
			break; /* end of headers */

		if (header_insert(hdrs, buf) != 0)
			goto err;
		
		free(buf);
	}

	ret = 0;
err:
	free(buf);
	return (ret);
}

char *
http_response(FILE *fp, size_t *len)
{
	char	*buf;
	size_t	 ln;

	if ((buf = fparseln(fp, &ln, NULL, "\0\0\0", 0)) == NULL) {
		warn("%s", __func__);
		return (NULL);
	}

	if (ln > 0 && buf[ln - 1] == '\r')
		buf[--ln] = '\0';

	*len = ln;
	return (buf);
}

int
http_response_code(FILE *fp)
{
	char		*buf;
	size_t		 len;
	int		 res;

	buf = http_response(fp, &len);
	res = response_code(buf);
	free(buf);
	return (res);
}

