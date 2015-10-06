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
#include <sys/socket.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "http.h"
#include "progressmeter.h"

const char	*scheme_str(int);
int		 unsafe_char(const char *);

int	ftp_debug = 0;

int
tcp_connect(const char *host, const char *port)
{
	struct addrinfo	 hints, *res, *res0;
	char		 hbuf[NI_MAXHOST];
	const char	*cause = NULL;
	int		 error, s = -1, save_errno;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &res0);
	if (error) {
		warnx("%s: %s", host, gai_strerror(error));
		return (-1);
	}

	for (res = res0; res; res = res->ai_next) {
		if (getnameinfo(res->ai_addr, res->ai_addrlen, hbuf,
		    sizeof(hbuf), NULL, 0, NI_NUMERICHOST) != 0)
			(void)strlcpy(hbuf, "(unknown)", sizeof(hbuf));

		log_info("Trying %s...", hbuf);
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1) {
			cause = "socket";
			continue;
		}

		if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "connect";
			save_errno = errno;
			close(s);
			errno = save_errno;
			s = -1;
			continue;
		}

		break;
	}

	freeaddrinfo(res0);
	if (s == -1) {
		warn("%s", cause);
		return (-1);
	}

	return (s);
}

/*
 * Determine whether the character needs encoding, per RFC1738:
 * 	- No corresponding graphic US-ASCII.
 * 	- Unsafe characters.
 */
int
unsafe_char(const char *c0)
{
	const char *unsafe_chars = " <>\"#{}|\\^~[]`";
	const unsigned char *c = (const unsigned char *)c0;

	/*
	 * No corresponding graphic US-ASCII.
	 * Control characters and octets not used in US-ASCII.
	 */
	return (iscntrl(*c) || !isascii(*c) ||

	    /*
	     * Unsafe characters.
	     * '%' is also unsafe, if is not followed by two
	     * hexadecimal digits.
	     */
	    strchr(unsafe_chars, *c) != NULL ||
	    (*c == '%' && (!isxdigit(*++c) || !isxdigit(*++c))));
}

/*
 * Encode given URL, per RFC1738.
 * Allocate and return string to the caller.
 */
char *
url_encode(const char *path)
{
	size_t i, length, new_length;
	char *epath, *epathp;

	length = new_length = strlen(path);

	/*
	 * First pass:
	 * Count unsafe characters, and determine length of the
	 * final URL.
	 */
	for (i = 0; i < length; i++)
		if (unsafe_char(path + i))
			new_length += 2;

	epath = epathp = malloc(new_length + 1);	/* One more for '\0'. */
	if (epath == NULL)
		err(1, "Can't allocate memory for URL encoding");

	/*
	 * Second pass:
	 * Encode, and copy final URL.
	 */
	for (i = 0; i < length; i++)
		if (unsafe_char(path + i)) {
			snprintf(epathp, 4, "%%" "%02x",
			    (unsigned char)path[i]);
			epathp += 3;
		} else
			*(epathp++) = path[i];

	*epathp = '\0';
	return (epath);
}

int
header_insert(struct http_hdrs *hdrs, const char *buf)
{
	const char	*errstr;
	size_t		 sz;

	if (strncasecmp(buf, "Content-Length: ", 16) == 0) {
		buf = strchr(buf, ' ');
		buf++;
		hdrs->c_len = strtonum(buf, 0, INT64_MAX, &errstr);
		if (errstr) {
			warn("%s: strtonum", __func__);
			return (-1);
		}
	}

	if (strncasecmp(buf, "Location: ", 10) == 0) {
		buf = strchr(buf, ' ');
		buf++;
		sz = strlcpy(hdrs->location, buf, sizeof(hdrs->location));
		if (sz >= sizeof(hdrs->location)) {
			warnx("%s: Location overflow", __func__);
			return (-1);
		}
	}

	return (0);
}

void
retr_file(FILE *fp, const char *fn, off_t file_sz, off_t offset)
{
	size_t		 r, wlen;
	ssize_t		 i;
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
	while ((r = fread(buf, sizeof(char), TMPBUF_LEN, fp)) > 0) {
		if (ferror(fp))
			err(1, "%s: fread", __func__);
		offset += r;
		for (cp = buf, wlen = r; wlen > 0; wlen -= i, cp += i) {
			if ((i = write(fd, cp, wlen)) == -1) {
				if (errno != EINTR)
					err(1, "%s: write", __func__);
			} else if (i == 0)
				break;
		}
	}
	if (ferror(fp))
		err(1, "%s: fread", __func__);

	if (strcmp(fn, "-") != 0)
		close(fd);

	stop_progress_meter();
}

void
send_cmd(FILE *fp, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vsend_cmd(fp, fmt, ap);
	va_end(ap);
}

void
vsend_cmd(FILE *fp, const char *fmt, va_list ap)
{
	va_list	ap2;

	if (ftp_debug) {
		va_copy(ap2, ap);
		fprintf(stderr, ">>> ");
		vfprintf(stderr, fmt, ap2);
		fprintf(stderr, "\n");
		va_end(ap2);
	}

	if (vfprintf(fp, fmt, ap) == -1)
		errx(1, "vsend_cmd: vfprintf failed");

	if (fprintf(fp, "\r\n") == -1)
		errx(1, "vsend_cmd: fprintf failed");

	if (fflush(fp) != 0)
		err(1, "vsend_cmd: fflush");
}

int
http_response_code(char *buf)
{
	const char	*errstr;
	char		*p, *q;
	int		 res;

	if ((p = strchr(buf, ' ')) == NULL) {
		warnx("%s: Malformed response", __func__);
		return (-1);
	}

	p++;
	if ((q = strchr(p, ' ')) == NULL) {
		warnx("%s: Malformed response", __func__);
		return (-1);
	}

	*q = '\0';
	res = strtonum(p, 200, 503, &errstr);
	if (errstr) {
		warn("%s: strtonum", __func__);
		return (-1);
	}

	return (res);
}

void
log_info(const char *fmt, ...)
{
	va_list		ap;

	if (verbose == 0)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

void
log_request(struct url *url, struct url *proxy)
{
	int custom_port = 0;

	switch (url->scheme) {
	case HTTP:
		custom_port = strcmp(url->port, "80") ? 1 : 0;
		break;
	case HTTPS:
		custom_port = strcmp(url->port, "443") ? 1 : 0;
		break;
	case FTP:
		custom_port = strcmp(url->port, "21") ? 1 : 0;
		break;
	}

	if (proxy)
		log_info("Requesting %s://%s%s%s%s"
		    " (via %s://%s%s%s)",
		    scheme_str(url->scheme),
		    url->host,
		    custom_port ? ":" : "",
		    custom_port ? url->port : "",
		    url->path ? url->path : "",

		    /* via proxy part */
		    (proxy->scheme == HTTP) ? "http" : "https",
		    proxy->host,
		    proxy->port[0] ? ":" : "",
		    proxy->port[0] ? proxy->port : "");
	else
		log_info("Requesting %s://%s%s%s%s",
		    scheme_str(url->scheme),
		    url->host,
		    custom_port ? ":" : "",
		    custom_port ? url->port : "",
		    url->path ? url->path : "");
}

const char *
scheme_str(int scheme)
{
	switch (scheme) {
	case HTTP:
		return ("http");
	case HTTPS:
		return ("https");
	case FTP:
		return ("ftp");
	}

	return ("???");
}

const char *
http_errstr(int code)
{
	static char buf[32];

	switch (code) {
	case 400:
		return ("400 Bad Request");
	case 402:
		return ("402 Payment Required");
	case 403:
		return ("403 Forbidden");
	case 404:
		return ("404 Not Found");
	case 405:
		return ("405 Method Not Allowed");
	case 406:
		return ("406 Not Acceptable");
	case 408:
		return ("408 Request Timeout");
	case 409:
		return ("409 Conflict");
	case 410:
		return ("410 Gone");
	case 411:
		return ("411 Length Required");
	case 413:
		return ("413 Payload Too Long");
	case 414:
		return ("414 URI Too Long");
	case 415:
		return ("415 Unsupported Media Type");
	case 417:
		return ("417 Expectation Failed");
	case 426:
		return ("426 Upgrade Required");
	case 500:
		return ("500 Internal Server Error");
	case 501:
		return ("501 Not Implemented");
	case 502:
		return ("502 Bad Gateway");
	case 503:
		return ("503 Service Unavailable");
	case 504:
		return ("504 Gateway Timeout");
	case 505:
		return ("505 HTTP Version Not Supported");
	default:
		(void)snprintf(buf, sizeof(buf), "%d ???", code);
		return (buf);
	}
}
