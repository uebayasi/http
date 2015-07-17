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

#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "http.h"

#define USER_AGENT	"OpenBSD http"
#define MAX_RETRIES	10

char		*abs_url_str(char *, struct url *);
struct proto	*lookup(int);
int		 proto_type(const char *);
void		 usage(void);

#ifndef SMALL
const char	*cookiefile;
char		*tls_options;
#endif
const char	*ua = USER_AGENT;
int		 verbose = 1;

int
main(int argc, char *argv[])
{
	struct url	 url, proxy, *pproxy = NULL;
	struct headers	 res_hdrs;
	struct proto	*proto;
	char		*proxy_str, *url_str;
	const char	*fn, *output = NULL, *port = NULL;
	int		 ch, code, i, p, resume = 0, retries = 0;

#ifndef SMALL
	cookiefile = getenv("http_cookies");
#endif

	while ((ch = getopt(argc, argv, "c:Co:P:S:U:V")) != -1) {
		switch (ch) {
#ifndef SMALL
		case 'c':
			cookiefile = optarg;
			break;
		case 'S':
			tls_options = optarg;
			break;
#endif
		case 'C':
			resume = 1;
			break;
		case 'o':
			output = optarg;
			break;
		case 'P':
			port = optarg;
			break;
		case 'U':
			ua = optarg;
			break;
		case 'V':
			verbose = 0;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc == 0)
		usage();

	if ((proxy_str = getenv("http_proxy")) != NULL && *proxy_str == '\0')
		proxy_str = NULL;

	if (proxy_str) {
		p = proto_type(proxy_str);
		if (p == UNDEF)
			errx(1, "Unknown proxy protocol: %s\n", proxy_str);
		else if (p == FTP)
			errx(1, "Invalid proxy protocol: %s\n", proxy_str);

		if (url_parse(proxy_str, &proxy, p) != 0)
			errx(1, "Malformed proxy URL: %s", proxy_str);
		else
			pproxy = &proxy;
	}

	for (i = 0; i < argc; i++) {
retry:
		fn = (output) ? output : basename(argv[i]);
		url_str = url_encode(argv[i]);
		if ((p = proto_type(url_str)) == UNDEF)
			errx(1, "Unknown protocol: %s\n", argv[i]);

		if (url_parse(url_str, &url, p) != 0)
			errx(1, "Malformed URL: %s", url_str);

		if (p == FTP && port)
			(void)strlcpy(url.port, port, sizeof(url.port));

		proto = lookup(p);
		if (proto->connect(&url, pproxy) == -1)
			return (-1);

		log_request(&url, pproxy);
		memset(&res_hdrs, 0, sizeof(res_hdrs));
		code = proto->get(&url, fn, resume, &res_hdrs);
		switch (code) {
		case 200:	/* OK */
		case 206:	/* Partial Content */
			break;
		case 301:	/* Move Permanently */
		case 302:	/* Found */
		case 303:	/* See Other */
		case 307:	/* Temporary Redirect */
			if (++retries > MAX_RETRIES)
				errx(1, "Too many redirections requested");

			/* Relative redirects to absolute URL */
			if (res_hdrs.location[0] == '/')
				argv[i] = abs_url_str(res_hdrs.location, &url);
			else
				argv[i] = res_hdrs.location;

			free(url_str);
			log_info("Redirected to %s\n", res_hdrs.location);
			goto retry;
		case 416:	/* Range not Satisfiable */
			/* Ideally should check Content-Range header */
			warnx("File is already fully retrieved");
			break;
		default:
			errx(1, "Error retrieving file: %s", errstr(code));
		}

		retries = 0;
		free(url_str);
	}

	return (0);
}

char *
abs_url_str(char *url_str, struct url *orig_url)
{
	static char	abs_url[BUFSIZ];
	int		ret;

	ret = snprintf(abs_url, sizeof(abs_url), "%s://%s:%s%s",
	    (orig_url->proto == HTTP) ? "http" : "https",
	    orig_url->host,
	    orig_url->port,
	    url_str);

	if (ret == -1 || ret >= sizeof(abs_url))
		errx(1, "Cannot build redirect URL");

	return (abs_url);
}

struct proto *
lookup(int p)
{
	extern struct proto proto_http;
#ifndef SMALL
	extern struct proto proto_https;
	extern struct proto proto_ftp;
#endif

	switch (p) {
	case HTTP:
		return (&proto_http);
#ifndef SMALL
	case HTTPS:
		return (&proto_https);
	case FTP:
		return (&proto_ftp);
#endif
	}

	errx(1, "Invalid proto %d\n", p);
	return (NULL);
}

int
proto_type(const char *url)
{
	while (isblank((unsigned char)*url))
		url++;

	if (strncasecmp(url, "http://", 7) == 0)
		return (HTTP);
#ifndef SMALL
	else if (strncasecmp(url, "https://", 8) == 0)
		return (HTTPS);
	else if (strncasecmp(url, "ftp://", 6) == 0)
		return (FTP);
#endif
	else
		return (UNDEF);
}

void
usage(void)
{
#ifndef SMALL
	fprintf(stderr, "usage: %s [-C] [-c cookie] [-o output] "
	    "[-P port] [-S tls_options ] [-U useragent] url ...\n",
	    getprogname());
#else
	fprintf(stderr, "usage: %s [-C] [-o output] "
	    "[-P port] [-U useragent] url ...\n", getprogname());
#endif
	exit(0);
}

