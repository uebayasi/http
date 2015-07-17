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

int	 http_get(struct url *, const char *, int, struct headers *);
char	*http_getline(FILE *, size_t *);
int	 http_parse_headers(FILE *, struct headers *);
void	 http_ok(FILE *, int, off_t *);
int	 proxy_connect(int, struct url *, struct url *);

struct proto proto_http = {
	http_connect,
	http_get
};

extern const char	*ua;
static int		 s = -1;

void
http_init(void)
{
#ifndef SMALL
	cookie_load();
#endif
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

	host = (proxy) ? proxy->host : url->host;
	port = (proxy) ? proxy->port : url->port;

	if (port[0] == '\0')
		(void)strlcpy(url->port, "80", sizeof(url->port));

	if ((s = tcp_connect(host, port)) == -1)
		return (-1);

	if (proxy && proxy_connect(s, url, proxy) == -1)
		return (-1);

	return (s);
}

int
proxy_connect(int s, struct url *url, struct url *proxy)
{
	FILE		*fp;
	char		*buf;
	const char	*proxy_auth = NULL;
	size_t		 len;
	int		 code;

	if ((fp = fdopen(s, "r+")) == NULL)
		err(1, "http_connect: fdopen");

	if (proxy->user[0] || proxy->pass[0])
		proxy_auth = base64_encode(proxy->user, proxy->pass);

	fprintf(fp,
	    "CONNECT %s:%s HTTP/1.0\r\n"
	    "Host: %s\r\n"
	    "User-Agent: %s\r\n"
	    "%s%s"
	    "\r\n",
	    url->host,
	    (url->port[0]) ? url->port : "80",
	    url->host,
	    ua,
	    (proxy_auth) ? "Proxy-Authorization: Basic " : "",
	    (proxy_auth) ? proxy_auth : "");

	fflush(fp);
	if ((buf = http_getline(fp, &len)) == NULL)
		return (-1);

	if ((code = http_response_code(buf)) == -1) {
		free(buf);
		return (-1);
	}

	free(buf);
	if (code != 200)
		errx(1, "Error retrieving file: %s", errstr(code));

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
	char		*buf;
#ifndef SMALL
	char		*cookie;
#endif
	size_t		 len;
	int		 fd, flags, res = -1;

	if ((fin = fdopen(s, "r+")) == NULL)
		err(1, "http_get: fdopen");

	counter = 0;
	if (resume) {
		if (stat(out_fn, &sb) == -1)
			resume = 0;
		else {
			counter = sb.st_size;
			snprintf(range, sizeof(range),
			    "Range: bytes=%lld-\r\n", sb.st_size);
		}
	}

	if (url->user[0] || url->pass[0])
		basic_auth = base64_encode(url->user, url->pass);

#ifndef SMALL
	cookie_get(url->host, url->path, 0, &cookie);
#endif

	fprintf(fin,
	    "GET %s HTTP/1.0\r\n"
	    "Host: %s\r\n"
	    "User-Agent: %s\r\n"
	    "%s"
	    "%s%s"
#ifndef SMALL
	    "%s"
#endif
	    "\r\n",
	    (url->path[0]) ? url->path : "/",
	    url->host,
	    ua,
	    (resume) ? range : "",
	    (basic_auth) ? "Authorization: Basic " : "",
	    (basic_auth) ? basic_auth : ""
#ifndef SMALL
	    ,cookie ? cookie : ""
#endif
	    );

	fflush(fin);
	if ((buf = http_getline(fin, &len)) == NULL)
		goto cleanup;

	if ((res = http_response_code(buf)) == -1) {
		free(buf);
		goto cleanup;
	}

	free(buf);
	if (http_parse_headers(fin, hdrs) != 0) {
		res = -1;
		goto cleanup;
	}

	flags = O_CREAT | O_WRONLY;
	if (!resume)
		flags |= O_TRUNC;

	switch (res) {
	case 206:	/* Partial content */
		flags |= O_APPEND;
		/* FALLTHROUGH */
	case 200:	/* OK */
		if (strcmp(out_fn, "-") == 0)
			fd = STDOUT_FILENO;
		else if ((fd = open(out_fn, flags, 0666)) == -1)
			err(1, "http_get: open %s", out_fn);

		start_progress_meter(hdrs->c_len, &counter);
		http_ok(fin, fd, &counter);
		stop_progress_meter();
		break;
	}


cleanup:
	fclose(fin);
	return (res);
}

void
http_ok(FILE *fin, int out, off_t *ctr)
{
	size_t		 r, wlen;
	ssize_t		 i;
	char		*cp;
	static char	*buf;

	if (buf == NULL) {
		buf = malloc(TMPBUF_LEN); /* allocate once */
		if (buf == NULL)
			err(1, "http_ok: malloc");
	}

	while ((r = fread(buf, sizeof(char), TMPBUF_LEN, fin)) > 0) {
		*ctr += r;
		for (cp = buf, wlen = r; wlen > 0; wlen -= i, cp += i) {
			if ((i = write(out, cp, wlen)) == -1) {
				warn("http_ok: write");
				break;
			} else if (i == 0)
				break;
		}
	}
}

int
http_response_code(char *buf)
{
	const char	*errstr;
	char		*e;
	int		 res;

	if ((buf = strchr(buf, ' ')) == NULL) {
		warnx("http_response_code: Malformed response");
		return (-1);
	}

	buf++;
	if ((e = strchr(buf, ' ')) == NULL) {
		warnx("http_response_code: Malformed response");
		return (-1);
	}

	*e = '\0';
	res = strtonum(buf, 200, 503, &errstr);
	if (errstr) {
		warn("http_response_code: strtonum");
		return (-1);
	}

	return (res);
}

int
http_parse_headers(FILE *fin, struct headers *hdrs)
{
	char		*buf;
	size_t		 len;
	int		 ret;

	while ((buf = http_getline(fin, &len))) {
		if (len == 0)
			break; /* end of headers */

		if (header_insert(hdrs, buf) != 0) {
			ret = -1;
			goto exit;
		}
	}

	ret = 0;
exit:
	free(buf);
	return (ret);
}

char *
http_getline(FILE *fp, size_t *len)
{
	char	*buf;
	size_t	 ln;

	if ((buf = fparseln(fp, &ln, NULL, "\0\0\0", 0)) == NULL) {
		warn("http_getline");
		return (NULL);
	}

	if (buf[ln - 1] == '\r')
		buf[--ln] = '\0';

	*len = ln;
	return (buf);
}

