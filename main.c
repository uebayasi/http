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
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <netdb.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "http.h"

struct ftp_msg {
	off_t	offset;
	int	idx;
};

struct ftp_ack {
	int	code;
	int	idx;
};

#define USER_AGENT	"OpenBSD http"
#define MAX_REDIRECTS	10

static char		*absolute_url(char *, struct url *);
static void		 child(int, pid_t, int, char **);
static int		 download(int, struct ftp_msg *, int, char **);
static int		 handle_args(int, char **);
static const char	*output_filename(const char *);
static int		 read_message(struct imsgbuf *, struct imsg *, pid_t);
static void		 send_message(struct imsgbuf *, void *, size_t, int);
static int		 url_connect(struct url *);
static int		 url_get(struct url *, off_t, struct http_hdrs *);
static void		 url_parse(const char *, struct url *);
static void		 url_retr(int, int, off_t, off_t);
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
	struct url	 url;
	char		*url_str;
	int		 ch;

	if (pledge("dns inet stdio tty cpath rpath wpath "
	    "sendfd recvfd proc", NULL) == -1)
		err(1, "%s: pledge", __func__);

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
	ftp_debug = getenv("FTP_DEBUG") != NULL;

#ifndef SMALL
	switch (argc) {
	case 1:
		url_str = url_encode(argv[0]);
		url_parse(url_str, &url);
		free(url_str);
		ftp_connect(&url);
		/* FALLTHROUGH */
	case 0:
		ftp_command();
	}
#else
	if (argc == 0)
		usage();
#endif

	return handle_args(argc, argv);
}

static int
handle_args(int argc, char **argv)
{
	struct stat	 sb;
	struct imsgbuf	 ibuf;
	struct imsg	 imsg;
	struct ftp_msg	 msg;
	struct ftp_ack	*ack;
	pid_t		 pid, parent;
	const char	*fn;
	int		 i, fd, flags, pair[2], status;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pair) != 0)
		err(1, "socketpair");

	parent = getpid();
	switch (pid = fork()) {
	case -1:
		err(1, "fork");
	case 0:
		close(pair[0]);
		child(pair[1], parent, argc, argv);
	}

	close(pair[1]);
	if (pledge("stdio cpath rpath wpath sendfd", NULL) == -1)
		err(1, "%s: pledge", __func__);

	imsg_init(&ibuf, pair[0]);
	for (i = 0; i < argc; i++) {
		memset(&msg, 0, sizeof msg);
		msg.idx = i;
		flags = O_CREAT | O_WRONLY;
		fn = output_filename(argv[i]);
		if (resume && strcmp(fn, "-") && stat(fn, &sb) == 0) {
			msg.offset = sb.st_size;
			flags |= O_APPEND;
		}

		if (strcmp(fn, "-") == 0)
			fd = STDOUT_FILENO;
		else if ((fd = open(fn, flags, 0666)) == -1)
			err(1, "%s: open %s", __func__, fn);

		send_message(&ibuf, &msg, sizeof msg, fd);
		if (read_message(&ibuf, &imsg, pid) == 0)
			break;

		if (imsg.hdr.len != IMSG_HEADER_SIZE + sizeof *ack)
			errx(1, "message too small");

		ack = imsg.data;
		if (ack->idx != i)
			errx(1, "index mismatch");

		if (ack->code != 200 && ack->code != 206) {
			if (unlink(fn) == -1)
				err(1, "unlink");

			errx(1, "Error retrieving file: %s",
			    http_errstr(ack->code));
		}

		close(fd);
		imsg_free(&imsg);
	}

	close(pair[0]);
	while (waitpid(pid, &status, 0) == -1 && errno != ECHILD)
		if (errno != EINTR)
			err(1, "wait");

	if (WIFSIGNALED(status)) {
		if (unlink(fn) == -1)
			err(1, "unlink");

		errx(1, "child terminated; signal %d", WTERMSIG(status));
	}

	return 0;
}

static void
child(int fd, pid_t parent, int argc, char **argv)
{
	struct imsgbuf	 ibuf;
	struct imsg	 imsg;
	struct ftp_msg	*msg;
	struct ftp_ack	 ack;

	if (pledge("dns inet stdio rpath tty recvfd", NULL) == -1)
		err(1, "%s: pledge", __func__);

	imsg_init(&ibuf, fd);
	for (;;) {
		if (read_message(&ibuf, &imsg, parent) == 0)
			break;

		if (imsg.hdr.len != IMSG_HEADER_SIZE + sizeof *msg)
			errx(1, "message too small");

		if (imsg.fd == -1)
			errx(1, "%s: expected a file descriptor", __func__);

		msg = imsg.data;
		memset(&ack, 0, sizeof ack);
		ack.idx = msg->idx;
		ack.code = download(imsg.fd, msg, argc, argv);
		imsg_free(&imsg);
		send_message(&ibuf, &ack, sizeof ack, -1);
	}

	exit(0);
}

static int
download(int fd, struct ftp_msg *msg, int argc, char **argv)
{
	struct http_hdrs	 res_hdrs;
	struct url		 url;
	char			*url_str;
	off_t			 offset = msg->offset;
	int			 code = -1, idx = msg->idx, redirects = 0;

redirected:
	url_str = url_encode(argv[idx]);
	url_parse(url_str, &url);
	free(url_str);
	if (url_connect(&url) == -1)
		return -1;

	log_request(&url);
	memset(&res_hdrs, 0, sizeof res_hdrs);
	code = url_get(&url, offset, &res_hdrs);
	switch (code) {
	case 200:	/* OK */
		/* Expected partial content but got full content */
		if (offset) {
			offset = 0;
			if (ftruncate(fd, 0) == -1)
				err(1, "%s: ftruncate", __func__);
		}
		break;
	case 206:
		break;
	case 301:	/* Move Permanently */
	case 302:	/* Found */
	case 303:	/* See Other */
	case 307:	/* Temporary Redirect */
		if (++redirects > MAX_REDIRECTS)
			errx(1, "Too many redirections requested");

		/* Relative redirects to absolute URL */
		if (res_hdrs.location[0] == '/')
			argv[idx] = absolute_url(res_hdrs.location, &url);
		else
			argv[idx] = res_hdrs.location;

		log_info("Redirected to %s", res_hdrs.location);
		goto redirected;
	case 416:	/* Range not Satisfiable */
		/* Ideally should check Content-Range header */
		warnx("File is already fully retrieved");
		return 200;
	default:
		return code;
	}

	url_retr(fd, url.scheme, res_hdrs.c_len + offset, offset);
	free(url.path);
	return code;
}

static void
send_message(struct imsgbuf *ibuf, void *msg, size_t msglen, int fd)
{
	if (imsg_compose(ibuf, -1, -1, 0, fd, msg, msglen) != 1)
		err(1, "imsg_compose");
	if (imsg_flush(ibuf) != 0)
		err(1, "imsg_flush");
}

static int
read_message(struct imsgbuf *ibuf, struct imsg *imsg, pid_t from)
{
	int	n;

	if ((n = imsg_read(ibuf)) == -1)
		err(1, "imsg_read");
	if (n == 0)
		return (0);

	if ((n = imsg_get(ibuf, imsg)) == -1)
		err(1, "imsg_get");
	if (n == 0)
		return (0);

	if ((pid_t)imsg->hdr.pid != from)
		errx(1, "PIDs don't match");

	return (n);

}

struct url *
proxy_getenv(void)
{
	static struct url	*proxy = NULL;
	char			*proxy_str;
	static int		 inited = 0;

	/* Determine proxy just once */
	if (inited)
		return proxy;

	inited = 1;
	if ((proxy_str = getenv("http_proxy")) != NULL && *proxy_str == '\0')
		proxy_str = NULL;

	if (proxy_str == NULL)
		goto err;

	if ((proxy = malloc(sizeof *proxy)) == NULL)
		err(1, "%s: malloc", __func__);

	url_parse(proxy_str, proxy);
	if (proxy->scheme != HTTP)
		errx(1, "Invalid proxy scheme: %s", proxy_str);

	if (proxy->port[0] == '\0')
		(void)strlcpy(proxy->port, "80", sizeof proxy->port);

err:
	return proxy;
}

static const char *
output_filename(const char *url_str)
{
	const char	*fn, *p;
	int		scheme = 0;

	if (output)
		return output;

	if ((p = strstr(url_str, "://")) != NULL) {
		if (strncasecmp(url_str, "ftp://", 6) == 0)
			scheme = FTP;

		url_str = p + 3;
	}

	if ((fn = strrchr(url_str, '/')) != NULL)
		fn++;

	if (scheme != FTP && (fn == NULL || fn[0] == '\0'))
		errx(1, "No filename after host (use -o): %s", url_str);

	return fn;
}

static char *
absolute_url(char *url_str, struct url *orig_url)
{
	static char	abs_url[BUFSIZ];
	int		ret;

	ret = snprintf(abs_url, sizeof abs_url, "%s://%s:%s%s",
	    (orig_url->scheme == HTTP) ? "http" : "https",
	    orig_url->host,
	    orig_url->port,
	    url_str);

	if (ret == -1 || ret >= sizeof abs_url)
		errx(1, "Cannot build redirect URL");

	return abs_url;
}

static int
url_connect(struct url *url)
{
	int ret;

	switch (url->scheme) {
	case HTTP:
		ret = http_connect(url);
		break;
#ifndef SMALL
	case HTTPS:
		ret = https_connect(url);
		break;
	case FTP:
		ret = ftp_connect(url);
		break;
#endif
	default:
		errx(1, "%s: Invalid scheme", __func__);
	}

	return ret;
}

static int
url_get(struct url *url, off_t offset, struct http_hdrs *hdrs)
{
	int	ret;

	switch (url->scheme) {
	case HTTP:
		ret = http_get(offset, url, hdrs);
		break;
#ifndef SMALL
	case HTTPS:
		ret = https_get(offset, url, hdrs);
		break;
	case FTP:
		ret = ftp_get(offset, url);
		break;
#endif
	default:
		errx(1, "%s: Invalid scheme", __func__);
	}

	return ret;
}

static void
url_retr(int fd, int scheme, off_t file_sz, off_t offset)
{
	switch (scheme) {
	case HTTP:
		http_retr(fd, file_sz, offset);
		break;
#ifndef SMALL
	case HTTPS:
		https_retr(fd, file_sz, offset);
		break;
	case FTP:
		ftp_retr(fd, offset);
		break;
#endif
	default:
		errx(1, "%s: Invalid scheme", __func__);
	}
}

void
url_parse(const char *url_str, struct url *url)
{
	char	*t;

	memset(url, 0, sizeof *url);
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
		    url->basic_auth, sizeof url->basic_auth) == -1)
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
		if (strlcpy(url->port, t, sizeof url->port) >=
		    sizeof url->port)
			errx(1, "%s: port too long", __func__);
	}

	if (strlcpy(url->host, url_str, sizeof url->host) >=
	    sizeof url->host)
		errx(1, "%s: hostname too long", __func__);

	/* overwrite port with commandline argument if given */
	if (url->scheme == FTP && port)
		if (strlcpy(url->port, port, sizeof url->port)
		    >= sizeof url->port)
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

