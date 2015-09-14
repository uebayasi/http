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
#include <sys/tame.h>

#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "http.h"

#define USER_AGENT	"OpenBSD http"
#define MAX_RETRIES	10

char	*absolute_url(char *, struct url *);
int	 url_connect(struct url *, struct url *);
int	 url_get(struct url *, const char *, int, struct headers *);
void	 usage(void);

#ifndef SMALL
char		*tls_options;
#endif
const char	*ua = USER_AGENT;
int		 verbose = 1;

int
main(int argc, char *argv[])
{
	struct url	 url, proxy;
	struct headers	 res_hdrs;
	char		*proxy_str, *url_str;
	const char	*fn, *output = NULL, *port = NULL;
	const char	*paths[4] = { ".", "/etc/ssl", NULL, NULL };
	int		 ch, code, i, resume = 0, retries = 0;

	while ((ch = getopt(argc, argv, "Co:P:S:U:V")) != -1) {
		switch (ch) {
#ifndef SMALL
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

#ifdef SMALL
	/*
	 * "/etc/ssl" needn't be whitelisted for SMALL variant
	 * since we disable HTTPS support.
	 */
	paths[1] = output;
#else
	paths[2] = output;
#endif

	if (tame(TAME_DNS | TAME_INET | TAME_STDIO | TAME_IOCTL | 
	    TAME_CPATH | TAME_WPATH | TAME_ABORT, paths) != 0)
		err(1, "tame");

	if ((proxy_str = getenv("http_proxy")) != NULL && *proxy_str == '\0')
		proxy_str = NULL;

	if (proxy_str) {
		url_parse(proxy_str, &proxy);
		if (proxy.proto != HTTP)
			errx(1, "Invalid proxy protocol: %s", proxy_str);

		if (proxy.port[0] == '\0')
			(void)strlcpy(proxy.port, "www", sizeof(proxy.port));
	}

	for (i = 0; i < argc; i++) {
		fn = output ? output : basename(argv[i]);
		if (fn == NULL)
			err(1, "basename");
retry:
		url_str = url_encode(argv[i]);
		url_parse(url_str, &url);
		if (url.proto == FTP && port)
			if (strlcpy(url.port, port, sizeof(url.port))
			    >= sizeof(url.port))
				errx(1, "port overflow: %s", port);

		if (strcmp(url.path, "/") == 0 || strlen(url.path) == 0)
			errx(1, "No filename after host: %s", url.host);

		if (url_connect(&url, proxy_str ? &proxy : NULL) == -1)
			return (-1);

		log_request(&url, proxy_str ? &proxy : NULL);
		memset(&res_hdrs, 0, sizeof(res_hdrs));
		code = url_get(&url, fn, resume, &res_hdrs);
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
				argv[i] = absolute_url(res_hdrs.location, &url);
			else
				argv[i] = res_hdrs.location;

			free(url_str);
			log_info("Redirected to %s", res_hdrs.location);
			goto retry;
		case 416:	/* Range not Satisfiable */
			/* Ideally should check Content-Range header */
			warnx("File is already fully retrieved");
			break;
		case -1:
			return (-1);
		default:
			errx(1, "Error retrieving file: %s", http_errstr(code));
		}

		retries = 0;
		free(url_str);
	}

	return (0);
}

char *
absolute_url(char *url_str, struct url *orig_url)
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

int
url_connect(struct url *url, struct url *proxy)
{
	int ret;

	switch (url->proto) {
	case HTTP:
		ret = http_connect(url, proxy);
		break;
#ifndef SMALL
	case HTTPS:
		ret = https_connect(url, proxy);
		break;
	case FTP:
		if ((ret = ftp_connect(url, proxy)) == -1)
			errx(1, "Can't connect or login to host `%s'",
			    url->host);
		break;
#endif
	default:
		errx(1, "%s: Invalid protocol", __func__);
	}

	return (ret);
}

int
url_get(struct url *url, const char *fn, int resume, struct headers *hdrs)
{
	struct stat	sb;
	off_t		offset;
	int		ret;

	offset = 0;
	if (resume && strcmp(fn, "-") && stat(fn, &sb) == 0)
		offset = sb.st_size;

	switch (url->proto) {
	case HTTP:
		ret = http_get(fn, offset, url, hdrs);
		break;
#ifndef SMALL
	case HTTPS:
		ret = https_get(fn, offset, url, hdrs);
		break;
	case FTP:
		ret = ftp_get(fn, offset, url, hdrs);
		break;
#endif
	default:
		errx(1, "%s: Invalid protocol", __func__);
	}

	return (ret);
}

void
usage(void)
{
#ifndef SMALL
	fprintf(stderr, "usage: %s [-CV] [-o output] "
	    "[-P port] [-S tls_options ] [-U useragent] url ...\n",
	    getprogname());
#else
	fprintf(stderr, "usage: %s [-CV] [-o output] "
	    "[-P port] [-U useragent] url ...\n", getprogname());
#endif
	exit(1);
}

