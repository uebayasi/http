/*-
 * Copyright (c) 1997 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason Thorpe and Luke Mewburn.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

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

#include <sys/types.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "http.h"
#include "progressmeter.h"

int	 https_vprintf(struct tls *, const char *, ...);
char	*https_getline(struct tls *, size_t *);
int	 https_parse_headers(struct tls *, struct headers *);
void	 https_retr_file(struct tls *, int, off_t *);

struct tls_config	*https_init(void);

char * const tls_verify_opts[] = {
#define HTTP_TLS_CAFILE		0
	"cafile",
#define HTTP_TLS_CAPATH		1
	"capath",
#define HTTP_TLS_CIPHERS	2
	"ciphers",
#define HTTP_TLS_DONTVERIFY	3
	"dont",
#define HTTP_TLS_VERIFYDEPTH	4
	"depth",
	NULL
};

static struct tls	*ctx;

struct tls_config *
https_init(void)
{
	struct tls_config	*tls_config;
	extern char		*tls_options;
	char			*str;
	int			 depth;
	const char		*errstr;

	if (tls_init() != 0)
		errx(1, "tls init failed");

	if ((tls_config = tls_config_new()) == NULL)
		errx(1, "tls config_new failed");

	tls_config_set_protocols(tls_config, TLS_PROTOCOLS_ALL);
	if (tls_config_set_ciphers(tls_config, "compat") != 0)
		errx(1, "tls set ciphers failed");

	cookie_load();

	if (tls_options == NULL)
		return (tls_config);

	while (*tls_options) {
		switch (getsubopt(&tls_options, tls_verify_opts, &str)) {
		case HTTP_TLS_CAFILE:
			if (str == NULL)
				errx(1, "missing CA file");
			if (tls_config_set_ca_file(tls_config, str) != 0)
				errx(1, "tls ca file failed");
			break;
		case HTTP_TLS_CAPATH:
			if (str == NULL)
				errx(1, "missing ca path");
			if (tls_config_set_ca_path(tls_config, str) != 0)
				errx(1, "tls ca path failed");
			break;
		case HTTP_TLS_CIPHERS:
			if (str == NULL)
				errx(1, "missing cipher list");
			if (tls_config_set_ciphers(tls_config, str) != 0)
				errx(1, "tls set ciphers failed");
			break;
		case HTTP_TLS_DONTVERIFY:
			tls_config_insecure_noverifycert(tls_config);
			tls_config_insecure_noverifyname(tls_config);
			break;
		case HTTP_TLS_VERIFYDEPTH:
			if (str == NULL)
				errx(1, "missing depth");
			depth = strtonum(str, 0, INT_MAX, &errstr);
			if (errstr)
				errx(1, "Cert validation depth is %s", errstr);
			tls_config_set_verify_depth(tls_config, depth);
			break;
		default:
			errx(1, "Unknown -S suboption `%s'",
			    suboptarg ? suboptarg : "");
			/* NOTREACHED */
		}
	}

	return (tls_config);
}

int
https_connect(struct url *url, struct url *proxy)
{
	static struct tls_config	*tls_config = NULL;
	int				 s;

	/* One time initialization */
	if (tls_config == NULL)
		tls_config = https_init();

	if ((ctx = tls_client()) == NULL) {
		warnx("failed to create tls client");
		return (-1);
	}

	if (tls_configure(ctx, tls_config) != 0) {
		warnx("tls_configure: %s", tls_error(ctx));
		return (-1);
	}

	if (url->port[0] == '\0')
		(void)strlcpy(url->port, "443", sizeof(url->port));

	if ((s = http_connect(url, proxy)) == -1)
		return (-1);

	if (tls_connect_socket(ctx, s, url->host) != 0) {
		warnx("tls_connect: %s", tls_error(ctx));
		return (-1);
	}

	return (s);
}

int
https_get(struct url *url, const char *out_fn, int resume, struct headers *hdrs)
{
	struct stat		 sb;
	char			 range[BUFSIZ];
	const char		*basic_auth = NULL;
	char			*cookie, *buf;
	off_t			 counter;
	size_t			 len;
	int			 fd, flags, res = -1;
	extern const char	*ua;

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

	cookie_get(url->host, url->path, 1, &cookie);

	https_vprintf(ctx,
	    "GET https://%s%s%s%s HTTP/1.0\r\n"
	    "Host: %s\r\n"
	    "User-Agent: %s\r\n"
	    "%s"
	    "%s%s"
	    "%s"
	    "\r\n",
	    url->host,
	    (url->port[0]) ? ":" : "",
	    (url->port[0]) ? url->port : "",
	    url->path,
	    url->host,
	    ua,
	    (resume) ? range : "",
	    (basic_auth) ? "Authorization: Basic " : "",
	    (basic_auth) ? basic_auth : "",
	    cookie ? cookie : "");

	if ((buf = https_getline(ctx, &len)) == NULL)
		goto cleanup;

	if ((res = http_response_code(buf)) == -1)
		goto cleanup;

	if (https_parse_headers(ctx, hdrs) != 0) {
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
		if (strcmp(out_fn, "-") == 0)
			fd = STDOUT_FILENO;
		else if ((fd = open(out_fn, flags, 0666)) == -1)
			err(1, "https_get: open %s", out_fn);

		start_progress_meter(hdrs->c_len + counter, &counter);
		https_retr_file(ctx, fd, &counter);
		stop_progress_meter();
		if (fd != STDOUT_FILENO)
			close(fd);
		break;
	}

cleanup:
	free(buf);
	tls_close(ctx);
	tls_free(ctx);
	return (res);
}

void
https_retr_file(struct tls *tls, int out, off_t *ctr)
{
	size_t		 r, wlen;
	ssize_t		 i;
	char		*cp;
	static char	*buf;
	int		 ret;

	if (buf == NULL) {
		buf = malloc(TMPBUF_LEN); /* allocate once */
		if (buf == NULL)
			err(1, "https_retr_file: malloc");
	}

	while (1) {
		ret = tls_read(tls, buf, TMPBUF_LEN, &r);

		if (ret == TLS_READ_AGAIN || ret == TLS_WRITE_AGAIN)
			continue;
		if (ret != 0)
			errx(1, "https_retr_file: tls_read: %s",
			    tls_error(tls));

		if (r == 0)
			break;

		*ctr += r;
		for (cp = buf, wlen = r; wlen > 0; wlen -= i, cp += i) {
			if ((i = write(out, cp, wlen)) == -1) {
				if (errno != EINTR)
					err(1, "https_retr_file: write");
			} else if (i == 0)
				break;
		}
	}
}

int
https_vprintf(struct tls *tls, const char *fmt, ...)
{
	va_list	 ap;
	char	*string;
	size_t	 nw;
	int	 ret;

	va_start(ap, fmt);
	if ((ret = vasprintf(&string, fmt, ap)) == -1) {
		va_end(ap);
		return ret;
	}

	va_end(ap);
	ret = tls_write(tls, string, ret, &nw);
	free(string);
	return ret;
}

char *
https_getline(struct tls *tls, size_t *lenp)
{
	size_t	 i, len, nr;
	char	*buf, *q, c;
	int	 ret;

	len = 128;
	if ((buf = calloc(1, len)) == NULL)
		errx(1, "Can't allocate memory for transfer buffer");

	for (i = 0; ; i++) {
		if (i >= len - 1) {
			if ((q = reallocarray(buf, len, 2)) == NULL)
				errx(1, "Can't expand transfer buffer");

			buf = q;
			len *= 2;
		}
again:
		ret = tls_read(tls, &c, 1, &nr);
		if (ret == TLS_READ_AGAIN || ret == TLS_WRITE_AGAIN)
			goto again;

		if (ret != 0)
			errx(1, "TLS read error: %u", ret);

		buf[i] = c;
		if (c == '\n')
			break;
	}

	buf[i] = '\0';
	if (i && buf[i - 1] == '\r')
		buf[--i] = '\0';

	*lenp = i;
	return (buf);
}

int
https_parse_headers(struct tls *tls, struct headers *hdrs)
{
	char		*buf;
	size_t		 len;
	int		 ret;

	ret = 0;
	while ((buf = https_getline(tls, &len))) {
		if (len == 0)
			break; /* end of headers */

		if (header_insert(hdrs, buf) != 0) {
			ret = -1;
			goto exit;
		}

		free(buf);
	}

exit:
	free(buf);
	return (ret);
}
