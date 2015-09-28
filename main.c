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

#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "http.h"

#define USER_AGENT	"OpenBSD http"
#define MAX_REDIRECTS	10

static char		*absolute_url(char *, struct url *);
static int		 handle_args(int, char **);
static const char	*output_filename(struct url *);
static struct url	*proxy_getenv(void);
static int		 url_connect(struct url *, struct url *);
static int		 url_get(struct url *, const char *, struct headers *);
static void		 url_parse(const char *, struct url *);
static void		 usage(void);

#ifndef SMALL
char		*tls_options;
#endif
const char	*ua = USER_AGENT;
int		 verbose = 1;

static const char	*output, *port;
static int		 resume;

int
main(int argc, char *argv[])
{
	const char	*paths[4] = { ".", "/etc/ssl", NULL, NULL };
	int		 ch;

	while ((ch = getopt(argc, argv, "Co:P:S:U:V")) != -1) {
		switch (ch) {
		case 'C':
			resume = 1;
			break;
		case 'o':
			output = optarg;
			break;
		case 'P':
			port = optarg;
			break;
#ifndef SMALL
		case 'S':
			tls_options = optarg;
			break;
#endif
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

#ifdef SMALL
	/*
	 * "/etc/ssl" needn't be whitelisted for SMALL variant
	 * since we disable HTTPS support.
	 */
	paths[1] = output;
#else
	paths[2] = output;
#endif

	if (tame("dns inet stdio ioctl cpath wpath", paths) != 0)
		err(1, "tame");

#ifndef SMALL
	if (argc == 0)
		ftp_command(NULL);
#endif

	return (handle_args(argc, argv));
}

static struct url *
proxy_getenv(void)
{
	static struct url	 proxy;
	char			*proxy_str;

	if ((proxy_str = getenv("http_proxy")) != NULL && *proxy_str == '\0')
		proxy_str = NULL;

	if (proxy_str == NULL)
		return (NULL);

	url_parse(proxy_str, &proxy);
	if (proxy.scheme != HTTP)
		errx(1, "Invalid proxy scheme: %s", proxy_str);

	if (proxy.port[0] == '\0')
		(void)strlcpy(proxy.port, "80", sizeof(proxy.port));

	return (&proxy);
}

static int
handle_args(int argc, char *argv[])
{
	struct url	*proxy, url;
	struct headers	 res_hdrs;
	const char	*fn = NULL;
	char		*url_str;
	int		 code, i, redirects = 0;

	proxy = proxy_getenv();
	for (i = 0; i < argc; i++) {
redirected:
		url_str = url_encode(argv[i]);
		url_parse(url_str, &url);
		free(url_str);
		/* evaluate fn just once in case of redirects */
		if (fn == NULL)
			fn = output_filename(&url);

		if (url_connect(&url, proxy) == -1)
			return (1);

		log_request(&url, proxy);
		memset(&res_hdrs, 0, sizeof(res_hdrs));
		code = url_get(&url, fn, &res_hdrs);
		switch (code) {
		case 200:	/* OK */
		case 206:	/* Partial Content */
			break;
		case 301:	/* Move Permanently */
		case 302:	/* Found */
		case 303:	/* See Other */
		case 307:	/* Temporary Redirect */
			if (++redirects > MAX_REDIRECTS)
				errx(1, "Too many redirections requested");

			/* Relative redirects to absolute URL */
			if (res_hdrs.location[0] == '/')
				argv[i] = absolute_url(res_hdrs.location, &url);
			else
				argv[i] = res_hdrs.location;

			log_info("Redirected to %s", res_hdrs.location);
			goto redirected;
		case 416:	/* Range not Satisfiable */
			/* Ideally should check Content-Range header */
			warnx("File is already fully retrieved");
			break;
		case -1:
			return (1);
		default:
			errx(1, "Error retrieving file: %s", http_errstr(code));
		}

		free(url.path);
		redirects = 0;
		fn = NULL;
	}

	return (0);
}

static const char *
output_filename(struct url *url)
{
	const char	*fn = NULL;

	if (output)
		return (output);

	if (url->path && (fn = strrchr(url->path, '/')) != NULL)
		fn++;

	if (url->scheme != FTP && (fn == NULL || fn[0] == '\0'))
		errx(1, "No filename after host (use -o): %s", url->host);

	return (fn);
}

static char *
absolute_url(char *url_str, struct url *orig_url)
{
	static char	abs_url[BUFSIZ];
	int		ret;

	ret = snprintf(abs_url, sizeof(abs_url), "%s://%s:%s%s",
	    (orig_url->scheme == HTTP) ? "http" : "https",
	    orig_url->host,
	    orig_url->port,
	    url_str);

	if (ret == -1 || ret >= sizeof(abs_url))
		errx(1, "Cannot build redirect URL");

	return (abs_url);
}

static int
url_connect(struct url *url, struct url *proxy)
{
	int ret;

	switch (url->scheme) {
	case HTTP:
		ret = http_connect(url, proxy);
		break;
#ifndef SMALL
	case HTTPS:
		ret = https_connect(url, proxy);
		break;
	case FTP:
		ret = ftp_connect(url, proxy);
		break;
#endif
	default:
		errx(1, "%s: Invalid scheme", __func__);
	}

	return (ret);
}

static int
url_get(struct url *url, const char *fn, struct headers *hdrs)
{
	struct stat	sb;
	off_t		offset;
	int		ret;

	offset = 0;
	if (resume && strcmp(fn, "-") && stat(fn, &sb) == 0)
		offset = sb.st_size;

	switch (url->scheme) {
	case HTTP:
		ret = http_get(fn, offset, url, hdrs);
		break;
#ifndef SMALL
	case HTTPS:
		ret = https_get(fn, offset, url, hdrs);
		break;
	case FTP:
		ret = ftp_get(fn, offset, url);
		break;
#endif
	default:
		errx(1, "%s: Invalid scheme", __func__);
	}

	return (ret);
}

void
url_parse(const char *url_str, struct url *url)
{
	char	*t;

	memset(url, 0, sizeof(*url));
	while (isblank((unsigned char)*url_str))
		url_str++;

	/* Determine the scheme */
	if ((t = strstr(url_str, "://")) != NULL) {
		if (strncasecmp(url_str, "http://", 7) == 0)
			url->scheme = HTTP;
		else if (strncasecmp(url_str, "https://", 8) == 0)
			url->scheme = HTTPS;
		else if (strncasecmp(url_str, "ftp://", 6) == 0)
			url->scheme = FTP;
		else
			errx(1, "%s: Invalid scheme %s", __func__, url_str);

		url_str = t + 3;
	} else
		url->scheme = FTP;	/* default to FTP */

	/* Prepare Basic Auth of credentials if present */
	if ((t = strchr(url_str, '@')) != NULL) {
		if (b64_ntop((unsigned char *)url_str, t - url_str,
		    url->basic_auth, sizeof(url->basic_auth)) == -1)
			errx(1, "error in base64 encoding");

		url_str = ++t;
	}

	/* Extract path component */
	if ((t = strchr(url_str, '/')) != NULL) {
		if ((url->path = strdup(t)) == NULL)
			err(1, "%s: strdup", __func__);

		*t = '\0';
	}

	/* hostname and port */
	if ((t = strchr(url_str, ':')) != NULL)	{
		*t++ = '\0';
		if (strlcpy(url->port, t, sizeof(url->port)) >=
		    sizeof(url->port))
			errx(1, "%s: port too long", __func__);
	}

	if (strlcpy(url->host, url_str, sizeof(url->host)) >=
	    sizeof(url->host))
		errx(1, "%s: hostname too long", __func__);

	/* overwrite port with commandline argument if given */
	if (url->scheme == FTP && port)
		if (strlcpy(url->port, port, sizeof(url->port))
		    >= sizeof(url->port))
			errx(1, "%s: port overflow: %s", __func__, port);
}

static void
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

