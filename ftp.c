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

#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <err.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>
#include <unistd.h>

#include "http.h"

#define POSITIVE_PRE	100
#define POSITIVE_OK	200
#define POSITIVE_INTER	300
#define NEGATIVE_TRANS	400
#define NEGATIVE_PERM	500

static FILE	*ctrl_fp;

static int	 ftp_auth(const char *, const char *);
static char	*ftp_parseln(void);
static int	 ftp_pasv(void);
static int	 ftp_response(char **);
static int	 ftp_send_cmd(const char *, char **, const char *fmt, ...)
		    __attribute__((__format__ (printf, 3, 4)))
		    __attribute__((__nonnull__ (3)));
static off_t	 ftp_size(const char *);

int
ftp_connect(struct url *url, struct url *proxy)
{
	const char	*host, *port;
	int		 ctrl_sock;

	if (url->port[0] == '\0')
		(void)strlcpy(url->port, "ftp", sizeof(url->port));

	host = proxy ? proxy->host : url->host;
	port = proxy ? proxy->port : url->port;
	if ((ctrl_sock = tcp_connect(host, port)) == -1)
		return (-1);

	if ((ctrl_fp = fdopen(ctrl_sock, "r+")) == NULL)
		err(1, "%s: fdopen", __func__);

	if (proxy && proxy_connect(ctrl_fp, url, proxy) == -1)
		return (-1);

	/* read greeting */
	if (ftp_response(NULL) != POSITIVE_OK)
		return (-1);

	log_info("Connected to %s", url->host);
	if (ftp_auth(url->user, url->pass) == -1)
		return (-1);

	return (ctrl_sock);
}

int
ftp_get(const char *fn, off_t offset, struct url *url, struct headers *hdrs)
{
	FILE		*data_fp;
	char		*dir, *file;
	off_t		 file_sz;
	int	 	 code, data_sock, ret;

	log_info("Using binary mode to transfer files.");
	if (ftp_send_cmd(__func__, NULL, "TYPE I") != POSITIVE_OK)
		return (-1);

	if ((dir = dirname(url->path)) == NULL)
		err(1, "%s: dirname", __func__);

	if ((file = basename(url->path)) == NULL)
		err(1, "%s: basename", __func__);

	if (strcmp(dir, "/") != 0) {
		if (ftp_send_cmd(__func__, NULL, "CWD %s", dir) != POSITIVE_OK)
			errx(1, "%s: %s No such file or directory",
			    __func__, dir);
	}

	file_sz = ftp_size(file);
	if ((data_sock = ftp_pasv()) == -1)
		return (-1);

	if ((data_fp = fdopen(data_sock, "r+")) == NULL)
		err(1, "%s: fdopen", __func__);

	if (offset) {
		code = ftp_send_cmd(__func__, NULL, "REST %lld", offset);
		if (code != POSITIVE_OK || code != POSITIVE_INTER) {
			offset = 0;
			if (truncate(fn, 0) == -1)
				err(1, "%s: truncate", __func__);
		}
	}

	/* Data connection established */
	if (ftp_send_cmd(__func__, NULL, "RETR %s", file) != POSITIVE_PRE)
	if (code != POSITIVE_PRE)
		return (-1);

	retr_file(data_fp, fn, file_sz, offset);
	if ((ret = ftp_response(NULL)) != POSITIVE_OK)
		return (-1);

	(void)ftp_send_cmd(__func__, NULL, "QUIT");
	return (ret);
}

static off_t
ftp_size(const char *fn)
{
	char		*buf, *s;
	const char	*errstr;
	off_t	 	 file_sz;
	int		 old_verbose;

	old_verbose = verbose;
	verbose = 0;
	file_sz = 0;
	if (ftp_send_cmd(__func__, &buf, "SIZE %s", fn) == POSITIVE_OK) {
		if ((s = strchr(buf, ' ')) != NULL) {
			s++;
			file_sz = strtonum(s, 0, LLONG_MAX, &errstr);
			if (errstr)
				err(1, "%s: strtonum", __func__);
		}
	}

	free(buf);
	verbose = old_verbose;
	return (file_sz);
}

#define pack2(var, off) \
	(((var[(off) + 0] & 0xff) << 8) | ((var[(off) + 1] & 0xff) << 0))
#define pack4(var, off) \
	(((var[(off) + 0] & 0xff) << 24) | ((var[(off) + 1] & 0xff) << 16) | \
	 ((var[(off) + 2] & 0xff) << 8) | ((var[(off) + 3] & 0xff) << 0))

/* 
 * Parse PASV response and return a socket descriptor to the data stream.
 */
static int
ftp_pasv(void)
{
	struct sockaddr_in	 data_addr;
	char			*buf, *s, *e;
	uint			 addr[4], port[2];
	int			 sock, ret;

	memset(&addr, 0, sizeof(addr));
	memset(&port, 0, sizeof(port));
	if (ftp_send_cmd(__func__, &buf, "PASV") != POSITIVE_OK)
		return (-1);

	if ((s = strchr(buf, '(')) == NULL || (e = strchr(s, ')')) == NULL) {
		warnx("Malformed PASV reply");
		free(buf);
		return (-1);
	}

	s++;
	*e = '\0';
	ret = sscanf(s, "%u,%u,%u,%u,%u,%u",
	    &addr[0], &addr[1], &addr[2], &addr[3],
	    &port[0], &port[1]);

	if (ret != 6) {
		warnx("Passive mode address scan failure");
		return (-1);
	}

	free(buf);
	memset(&data_addr, 0, sizeof(data_addr));
	data_addr.sin_family = AF_INET;
	data_addr.sin_len = sizeof(struct sockaddr_in);
	data_addr.sin_addr.s_addr = htonl(pack4(addr, 0));
	data_addr.sin_port = htons(pack2(port, 0));

	if ((sock = socket(data_addr.sin_family, SOCK_STREAM, 0)) == -1)
		err(1, "%s: socket", __func__);

	if (connect(sock, (struct sockaddr *)&data_addr,
	    data_addr.sin_len) == -1)
		err(1, "%s: connect", __func__);

	return (sock);
}

static int
ftp_auth(const char *user, const char *pass)
{
	int	code;

	if (user[0])
		code = ftp_send_cmd(__func__, NULL, "USER %s", user);
	else
		code = ftp_send_cmd(__func__, NULL, "USER %s", "anonymous");

	if (code != POSITIVE_OK && code != POSITIVE_INTER)
		return (-1);

	if (pass[0])
		code = ftp_send_cmd(__func__, NULL, "PASS %s", pass);
	else
		code = ftp_send_cmd(__func__, NULL, "PASS user@hostname");

	if (code != POSITIVE_OK)
		return (-1);

	return (0);
}

static int
ftp_response(char **linep)
{
	char		*buf, *line;
	const char	*errstr;
	int		 code = -1;

	if ((line = ftp_parseln()) == NULL) {
		if (linep)
			*linep = NULL;
		return (code);
	}

	if ((buf = strndup(line, 3)) == NULL)
		err(1, "%s: strndup", __func__);

	/* validity: 100 < code < 553 */
	(void)strtonum(buf, POSITIVE_PRE, NEGATIVE_PERM + 53, &errstr);
	if (errstr)
		err(1, "%s: illegal response code %s", __func__, buf);

	free(buf);
	switch (line[0]) {
	case '1':
		code = POSITIVE_PRE;
		break;
	case '2':
		code = POSITIVE_OK;
		break;
	case '3':
		code = POSITIVE_INTER;
		break;
	case '4':
		code = NEGATIVE_TRANS;
		break;
	case '5':
		code = NEGATIVE_PERM;
		break;
	}

	if (linep)
		*linep = line;
	else
		free(line);
	
	return (code);
}

static char *
ftp_parseln(void)
{
	char		*buf;
	size_t		 len;

	buf = NULL;
	while ((buf = fparseln(ctrl_fp, &len, NULL, "\0\0\0", 0)) != NULL) {
		if (buf[len - 1] == '\r')
			buf[--len] = '\0';

		log_info("%s", buf);
		if (len == 3 || buf[3] == ' ')	/* last line */
			break;

		free(buf);
	}

	return (buf);
}

static int
ftp_send_cmd(const char *where, char **response_line, const char *fmt, ...)
{
	va_list	ap;

	va_start (ap, fmt);
	vsend_cmd(where, ctrl_fp, fmt, ap);
	va_end(ap);
	return (ftp_response(response_line));
}
