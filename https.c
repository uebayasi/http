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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "http.h"
#include "progressmeter.h"

static struct tls_config	*https_init(void);
static void			 https_vprintf(struct tls *, const char *, ...)
				    __attribute__((__format__ (printf, 2, 3)))
				    __attribute__((__nonnull__ (2)));
static char			*https_parseln(size_t *);
static int			 https_response(struct http_hdrs *);
static void			 https_retr_file(const char *, off_t, off_t);

static struct tls	*ctx;
char * const		 tls_verify_opts[] = {
			 #define HTTP_TLS_CAFILE		0
				"cafile",
			 #define HTTP_TLS_CAPATH		1
				"capath",
			 #define HTTP_TLS_CIPHERS		2
				"ciphers",
			 #define HTTP_TLS_DONTVERIFY		3
				"dont",
			 #define HTTP_TLS_VERIFYDEPTH		4
				"depth",
			 #define HTTP_TLS_PROTOCOLS		5
				"protocols",
				NULL
			};


struct tls_config *
https_init(void)
{
	struct tls_config	*tls_config;
	char			*str;
	int			 depth;
	uint32_t		 http_tls_protocols;
	const char		*errstr;

	if (tls_init() != 0)
		errx(1, "tls init failed");

	if ((tls_config = tls_config_new()) == NULL)
		errx(1, "tls config_new failed");

	tls_config_set_protocols(tls_config, TLS_PROTOCOLS_ALL);
	if (tls_config_set_ciphers(tls_config, "compat") != 0)
		errx(1, "tls set ciphers failed");

	if (tls_options == NULL)
		return tls_config;

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
		case HTTP_TLS_PROTOCOLS:
			if (tls_config_parse_protocols(&http_tls_protocols,
			    str) != 0)
				errx(1, "tls parsing protocols failed");
			tls_config_set_protocols(tls_config,
			    http_tls_protocols);
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
		}
	}

	return tls_config;
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
		return -1;
	}

	if (tls_configure(ctx, tls_config) != 0) {
		warnx("%s: %s", __func__, tls_error(ctx));
		return -1;
	}

	if (url->port[0] == '\0')
		(void)strlcpy(url->port, "443", sizeof(url->port));

	if ((s = http_connect(url, proxy)) == -1)
		return -1;

	if (tls_connect_socket(ctx, s, url->host) != 0) {
		warnx("%s: %s", __func__, tls_error(ctx));
		return -1;
	}

	return s;
}

int
https_get(const char *fn, off_t offset, struct url *url, struct http_hdrs *hdrs)
{
	char	range[BUFSIZ];
	int	res, ret;

	(void)snprintf(range, sizeof(range), "Range: bytes=%lld-\r\n", offset);
	https_vprintf(ctx,
	    "GET %s HTTP/1.0\r\n"
	    "Host: %s\r\n"
	    "User-Agent: %s\r\n"
	    "%s"
	    "%s%s"
	    "\r\n",
	    url->path ? url->path : "/",
	    url->host,
	    ua,
	    offset ? range : "",
	    url->basic_auth[0] ? "Authorization: Basic " : "",
	    url->basic_auth[0] ? url->basic_auth : "");
	res = https_response(hdrs);
	if (res != 200 && res != 206)
		goto err;

	/* Expected a partial content but got full content */
	if (offset && (res == 200)) {
		offset = 0;
		if (truncate(fn, 0) == -1)
			err(1, "%s: truncate", __func__);
	}

	https_retr_file(fn, hdrs->c_len + offset, offset);
err:
	while ((ret = tls_close(ctx)) != 0)
		if (ret != TLS_WANT_POLLIN && ret != TLS_WANT_POLLOUT)
			errx(1, "%s: tls_close: %s", __func__, tls_error(ctx));

	tls_free(ctx);
	return res;
}

static void
https_retr_file(const char *fn, off_t file_sz, off_t offset)
{
	size_t		 wlen;
	ssize_t		 i, r;
	char		*cp;
	static char	*buf;
	int		 fd, flags;

	if (buf == NULL) {
		buf = malloc(TMPBUF_LEN); /* allocate once */
		if (buf == NULL)
			err(1, "%s: malloc", __func__);
	}

	flags = O_CREAT | O_WRONLY;
	if (offset)
		flags |= O_APPEND;

	if (strcmp(fn, "-") == 0)
		fd = STDOUT_FILENO;
	else if ((fd = open(fn, flags, 0666)) == -1)
		err(1, "%s: open %s", __func__, fn);

	start_progress_meter(file_sz, &offset);
	while (1) {
		r = tls_read(ctx, buf, TMPBUF_LEN);
		if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
			continue;
		else if (r < 0) {
			errx(1, "%s: tls_read: %s", __func__, tls_error(ctx));
		}

		if (r == 0)
			break;

		offset += r;
		for (cp = buf, wlen = r; wlen > 0; wlen -= i, cp += i) {
			if ((i = write(fd, cp, wlen)) == -1) {
				if (errno != EINTR)
					err(1, "%s: write", __func__);
			} else if (i == 0)
				break;
		}
	}

	if (strcmp(fn, "-") != 0)
		close(fd);

	stop_progress_meter();
}

static int
https_response(struct http_hdrs *hdrs)
{
	char		*buf;
	size_t		 len;
	int		 res;

	buf = https_parseln(NULL);
	if (ftp_debug)
		fprintf(stderr, "<<< %s\n", buf);

	res = http_response_code(buf);
	free(buf);
	while ((buf = https_parseln(&len))) {
		if (len == 0)
			break;	/* end of headers */

		if (hdrs && header_insert(hdrs, buf) != 0)
			return -1;

		free(buf);
	}

	free(buf);
	return res;
}

static void
https_vprintf(struct tls *tls, const char *fmt, ...)
{
	va_list	 ap, ap2;
	char	*string;
	ssize_t	 nw;
	int	 len;

	va_start(ap, fmt);
	if (ftp_debug) {
		va_copy(ap2, ap);
		fprintf(stderr, ">>> ");
		vfprintf(stderr, fmt, ap2);
		va_end(ap2);
	}

	if ((len = vasprintf(&string, fmt, ap)) == -1)
		errx(1, "%s: vasprintf failed", __func__);
	va_end(ap);
again:
	nw = tls_write(tls, string, len);
	if (nw == TLS_WANT_POLLIN || nw == TLS_WANT_POLLOUT)
		goto again;
	else if (nw < 0)
		errx(1, "%s: tls_write: %s", __func__, tls_error(tls));

	free(string);
}

static char *
https_parseln(size_t *lenp)
{
	size_t	 i, len;
	char	*buf, *q, c;
	ssize_t	 nr;

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
		nr = tls_read(ctx, &c, 1);
		if (nr == TLS_WANT_POLLIN || nr == TLS_WANT_POLLOUT)
			goto again;

		if (nr < 0)
			errx(1, "TLS read error: %ld", nr);

		buf[i] = c;
		if (c == '\n')
			break;
	}

	buf[i] = '\0';
	if (i && buf[i - 1] == '\r')
		buf[--i] = '\0';

	if (lenp)
		*lenp = i;

	return buf;
}

