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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include "http.h"
#include "progressmeter.h"

void	 http_init(void);
int	 http_parse_headers(FILE *, struct headers *);
char	*http_response(FILE *, size_t *);
int	 proxy_connect(int, struct url *, struct url *);

extern const char	*ua;
static int		 s = -1;

void
http_init(void)
{
}

int
http_connect(struct url *url, struct url *proxy)
{
	const char	*host, *port;
	static int	 init = 0;

	/* One time initialization */
	if (init == 0) {
		http_init();
		init = 1;
	}

	if (url->port[0] == '\0')
		(void)strlcpy(url->port, "80", sizeof(url->port));

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
		err(1, "proxy_connect: fdopen");

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
	off_t		 counter;
	const char	*basic_auth = NULL;
	FILE		*fin;
	int		 flags, res = -1;

	if ((fin = fdopen(s, "r+")) == NULL)
		err(1, "http_get: fdopen");

	counter = 0;
	if (resume) {
		if (stat(out_fn, &sb) == 0) {
			counter = sb.st_size;
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
		goto cleanup;

	if (http_parse_headers(fin, hdrs) != 0) {
		res = -1;
		goto cleanup;
	}

	flags = O_CREAT | O_WRONLY;
	if (resume && (res == 206))
		flags |= O_APPEND;
	else {
		flags |= O_TRUNC;
		counter = 0;
	}

	switch (res) {
	case 206:	/* Partial content */
	case 200:	/* OK */
		start_progress_meter(hdrs->c_len + counter, &counter);
		retr_file(fin, out_fn, flags, &counter);
		stop_progress_meter();
		break;
	}

cleanup:
	fclose(fin);
	return (res);
}

int
http_parse_headers(FILE *fin, struct headers *hdrs)
{
	char		*buf;
	size_t		 len;
	int		 ret;

	while ((buf = http_response(fin, &len))) {
		if (len == 0)
			break; /* end of headers */

		if (header_insert(hdrs, buf) != 0) {
			ret = -1;
			goto exit;
		}
		
		free(buf);
	}

	ret = 0;
exit:
	free(buf);
	return (ret);
}

char *
http_response(FILE *fp, size_t *len)
{
	char	*buf;
	size_t	 ln;

	if ((buf = fparseln(fp, &ln, NULL, "\0\0\0", 0)) == NULL) {
		warn("http_response");
		return (NULL);
	}

	if (buf[ln - 1] == '\r')
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

