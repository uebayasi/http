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
#include <histedit.h>
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

#define	CMD_OPEN	1
#define	CMD_LS		2

static void	 do_open(int, const char **);
static void	 do_ls(int, const char **);
static int	 exec_cmd(int, const char **);
static char	*ftp_prompt(void);
static int	 ftp_auth(const char *, const char *);
static int	 ftp_pasv(void);
static int	 ftp_response(char **);
static int	 ftp_send_cmd(char **, const char *fmt, ...)
		    __attribute__((__format__ (printf, 2, 3)))
		    __attribute__((__nonnull__ (2)));
static int	 ftp_size(const char *, off_t *);

struct cmdtab {
	int		  command;
	char		 *name;
	int		  conn;
	const char	 *help;
	void		(*handler)(int, const char **);
} cmdtab[] = {
{ CMD_OPEN,	"open",	0,	"connect to remote ftp server", do_open },
{ CMD_LS,	"ls",	1,	"list contents of remote directory", do_ls },
{ 0 }
};

static FILE	*ctrl_fp;

int
ftp_connect(struct url *url, struct url *proxy)
{
	const char	*host, *port;
	int		 ctrl_sock;

	if (url->port[0] == '\0')
		(void)strlcpy(url->port, "21", sizeof(url->port));

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
		goto err;

	log_info("Connected to %s", url->host);
	if (ftp_auth("anonymous", "user@host") != POSITIVE_OK) {
		warnx("Login %s failed.", "anonymous");
		goto err;
	}

	if (url->path == NULL || strcmp(url->path, "/") == 0)
		ftp_command();
	else if (url->path[strlen(url->path) - 1] == '/') {
		if (ftp_send_cmd(NULL, "CWD %s", url->path) != POSITIVE_OK)
			goto err;

		ftp_command();
	}

	return (ctrl_sock);
err:
	warnx("Can't connect or login to host `%s'", url->host);
	ftp_send_cmd(NULL, "QUIT");
	return (-1);
}

int
ftp_get(const char *fn, off_t offset, struct url *url)
{
	FILE		*data_fp;
	char		*dir, *file;
	off_t		 file_sz;
	int		 code, data_sock, ret = -1;

	log_info("Using binary mode to transfer files.");
	if (ftp_send_cmd(NULL, "TYPE I") != POSITIVE_OK)
		goto err;

	file = strrchr(url->path, '/');
	if (file == NULL || file == url->path)
		dir = NULL;
	else {
		dir = url->path;
		*file++ = '\0';
	}
		
	if (dir && ftp_send_cmd(NULL, "CWD %s", dir) != POSITIVE_OK)
		goto err;

	if (ftp_size(file, &file_sz) != POSITIVE_OK) {
		log_info("failed to get size of file %s", file);
		goto err;
	}

	if ((data_sock = ftp_pasv()) == -1)
		goto err;

	if ((data_fp = fdopen(data_sock, "r+")) == NULL)
		err(1, "%s: fdopen", __func__);

	if (offset) {
		code = ftp_send_cmd(NULL, "REST %lld", offset);
		if (code != POSITIVE_OK && code != POSITIVE_INTER) {
			offset = 0;
			if (truncate(fn, 0) == -1)
				err(1, "%s: truncate", __func__);
		}
	}

	if (ftp_send_cmd(NULL, "RETR %s", file) != POSITIVE_PRE) {
		fclose(data_fp);
		goto err;
	}

	retr_file(data_fp, fn, file_sz, offset);
	fclose(data_fp);
	if ((ret = ftp_response(NULL)) != POSITIVE_OK)
		ret = -1;
err:
	(void)ftp_send_cmd(NULL, "QUIT");
	return (ret);
}

static int
ftp_size(const char *fn, off_t *sizep)
{
	char		*buf, *s;
	const char	*errstr;
	off_t		 file_sz;
	int		 code, old_verbose;

	old_verbose = verbose;
	verbose = 0;
	code = ftp_send_cmd(&buf, "SIZE %s", fn);
	verbose = old_verbose;
	if (code != POSITIVE_OK)
		return (code);

	if ((s = strchr(buf, ' ')) == NULL)
		return (NEGATIVE_PERM); /* Invalid reply */

	s++;
	file_sz = strtonum(s, 0, LLONG_MAX, &errstr);
	if (errstr)
		warnx("%s: strtonum", __func__);

	free(buf);
	if (sizep)
		*sizep = file_sz;

	return (code);
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
	int			 code, old_verbose, sock, ret;

	memset(&addr, 0, sizeof(addr));
	memset(&port, 0, sizeof(port));
	old_verbose = verbose;
	verbose = 0;
	code = ftp_send_cmd(&buf, "PASV");
	verbose = old_verbose;
	if (code != POSITIVE_OK)
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
		code = ftp_send_cmd(NULL, "USER %s", user);
	else
		code = ftp_send_cmd(NULL, "USER %s", "anonymous");

	if (code != POSITIVE_OK && code != POSITIVE_INTER)
		return (code);

	if (pass[0])
		code = ftp_send_cmd(NULL, "PASS %s", pass);
	else
		code = ftp_send_cmd(NULL, "PASS user@hostname");

	return (code);
}

static int
ftp_response(char **linep)
{
	char		*buf, *line;
	const char	*errstr;
	size_t		 len;
	int		 code = -1;

	line = http_parseln(ctrl_fp, &len);
	log_info("%s", line);
	if (len < 3)
		goto err;

	if ((buf = strndup(line, 3)) == NULL)
		err(1, "%s: strndup", __func__);

	(void)strtonum(buf, POSITIVE_PRE, NEGATIVE_PERM + 53, &errstr);
	if (errstr)
		err(1, "%s: illegal response code %s", __func__, buf);

	if (len >= 4 && line[3] == ' ')
		goto done;

	free(line);
	/* Multi-line reply, parse till the end */
	while ((line = http_parseln(ctrl_fp, &len))) {
		if (len >= 4 && strncasecmp(line, buf, 3) == 0 &&
		    line[3] == ' ') /* last line */
			break;

		log_info("%s", line);
		free(line);
	}

done:
	free(buf);
	/* line can never be NULL, but scan-build complains? */
	if (line == NULL)
		goto err;

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

err:
	if (linep)
		*linep = line;
	else
		free(line);

	return (code);
}

static int
ftp_send_cmd(char **response_line, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vsend_cmd(ctrl_fp, fmt, ap);
	va_end(ap);
	return (ftp_response(response_line));
}

void
ftp_command(void)
{
	HistEvent	 hev;
	EditLine	*el;
	History		*hist;
	Tokenizer	*tok;
	const char	*buf, **argv;
	int		 argc, len;

	if ((el = el_init(getprogname(), stdin, stdout, stderr)) == NULL)
		errx(1, "%s: el_init failed", __func__);

	if ((hist = history_init()) == NULL)
		errx(1, "%s: history_init failed", __func__);

	history(hist, &hev, H_SETSIZE, 100);
	el_set(el, EL_HIST, history, hist);
	el_set(el, EL_EDITOR, "emacs");
	el_set(el, EL_PROMPT, ftp_prompt);
	el_source(el, NULL);
	tok = tok_init(NULL);
	tok_reset(tok);
	while (1) {
		if ((buf = el_gets(el, &len)) == NULL || len == 0) {
			printf("\n");
			break;
		}

		if (strlen(buf) > 1)
			history(hist, &hev, H_ENTER, buf);

		tok_str(tok, buf, &argc, &argv);
		tok_reset(tok);
		if (exec_cmd(argc, argv) != 0)
			if (el_parse(el, argc, argv) != 0)
				printf("?Invalid command.\n");
	}

	history_end(hist);
	el_end(el);
	tok_end(tok);
	if (ctrl_fp)
		ftp_send_cmd(NULL, "QUIT");

	exit(0);
}

static int
exec_cmd(int argc, const char **argv)
{
	struct cmdtab	*c;

	for (c = cmdtab; c->command; c++)
		if (strcasecmp(argv[0], c->name) == 0)
			break;

	if (c->command == 0)
		return (1);

	if (c->conn && ctrl_fp == NULL)
		printf("Not connected\n");
	else
		c->handler(argc, argv);

	return (0);
}

static char *
ftp_prompt(void)
{
	return ("ftp> ");
}

static void
do_open(int argc, const char **argv)
{
	errx(1, "not yet");
}

static void
do_ls(int argc, const char **argv)
{
	errx(1, "not yet");
}
