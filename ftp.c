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
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <err.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>
#include <unistd.h>

#include "http.h"
#include "progressmeter.h"

static FILE	*ctrl_fin;
static int	 ctrl_sock = -1;

int	 ftp_auth(struct url *);
int	 ftp_check_response(const char *);
off_t	 ftp_size(const char *);
char	*ftp_response(void);
int	 ftp_pasv(void);
void	 interpret_command(struct url *);

int
ftp_connect(struct url *url, struct url *proxy)
{
	const char	*host, *port;
	char		*buf;
	size_t		 len;
	int		 code;

	if (url->port[0] == '\0')
		(void)strlcpy(url->port, "21", sizeof(url->port));

	host = (proxy) ? proxy->host : url->host;
	port = (proxy) ? proxy->port : url->port;

	if ((ctrl_sock = tcp_connect(host, port)) == -1)
		return (-1);

	if ((ctrl_fin = fdopen(ctrl_sock, "r+")) == NULL)
		err(1, "ftp_connect: fdopen");

	if (proxy) {
		fprintf(ctrl_fin, "CONNECT %s:%s\r\n", url->host, url->port);
		fflush(ctrl_fin);
		if ((buf = http_response(ctrl_fin, &len)) == NULL)
			return (-1);

		if ((code = http_response_code(buf)) == -1) {
			free(buf);
			return (-1);
		}

		free(buf);
		if (code != 200)
			errx(1, "Error retrieving file: %s", http_errstr(code));
	}

	log_info("Connected to %s\n", url->host);
	/* read greeting */
	if (ftp_check_response("2") != 0)
		return (-1);

	if (ftp_auth(url) == -1) {
		warnx("Login %s failed", url->user);
		return (-1);
	}

	if (url->path[strlen(url->path) - 1] == '/')
		interpret_command(url);

	return (ctrl_sock);
}

/* 
 * Just enough command interpretation for pkg_add(1) to function.
 */
void
interpret_command(struct url *url)
{
	FILE		*data_fin;
	char		*line;
	size_t		 len;
	int		 data_sock;

	if ((line = fparseln(stdin, &len, NULL, "\0\0\0", 0)) == NULL)
		exit(-1);

	if (strcasecmp(line, "nlist"))
		exit(-1);

	free(line);

	fprintf(ctrl_fin, "TYPE I\r\n");
	fflush(ctrl_fin);
	if (ftp_check_response("2") != 0)
		exit(-1);

	fprintf(ctrl_fin, "CWD %s\r\n", url->path);
	fflush(ctrl_fin);
	if (ftp_check_response("2") != 0)
		errx(1, "%s No such file or directory", url->path);

	fprintf(ctrl_fin, "TYPE A\r\n");
	fflush(ctrl_fin);
	if (ftp_check_response("2") != 0)
		exit(-1);

	if ((data_sock = ftp_pasv()) == -1)
		exit(-1);

	if ((data_fin = fdopen(data_sock, "r+")) == NULL)
		err(1, "interpret_command: fdopen");

	fprintf(ctrl_fin, "NLST\r\n");
	fflush(ctrl_fin);
	/* Data connection established */
	if (ftp_check_response("1") != 0)
		errx(1, "Data connection failed, shouldn't happen");

	while ((line = fparseln(data_fin, &len, NULL, "\0\0\0", 0)) != NULL) {
		printf("%s\n", line);
		free(line);
	}

	/* NLST response after the transfer completion */
	ftp_check_response("2");

	fprintf(ctrl_fin, "QUIT\r\n");
	fflush(ctrl_fin);
	ftp_check_response("2");

	exit(0);

}

int
ftp_get(struct url *url, const char *out_fn, int resume, struct headers *hdrs)
{
	struct stat	 sb;
	FILE		*data_fin;
	char		*dir, *file;
	off_t		 counter, file_sz;
	int	 	 data_sock, flags;

	log_info("Using binary mode to transfer files.\n");
	fprintf(ctrl_fin, "TYPE I\r\n");
	fflush(ctrl_fin);
	if (ftp_check_response("2") != 0)
		return (-1);

	dir = dirname(url->path);
	file = basename(url->path);
	if (strcmp(dir, "/") != 0) {
		fprintf(ctrl_fin, "CWD %s\r\n", dir);
		fflush(ctrl_fin);
		if (ftp_check_response("2") != 0)
			errx(1, "%s No such file or directory", dir);
	}

	file_sz = ftp_size(file);
	if ((data_sock = ftp_pasv()) == -1)
		return (-1);

	if ((data_fin = fdopen(data_sock, "r+")) == NULL)
		err(1, "ftp_get: fdopen");

	counter = 0;
	if (resume) {
		if (stat(out_fn, &sb) == 0) {
			fprintf(ctrl_fin, "REST %lld\r\n", sb.st_size);
			fflush(ctrl_fin);
			if (ftp_check_response("3") == 0)
				counter = sb.st_size;
			else
				resume = 0;
		} else
			resume = 0;
	}

	fprintf(ctrl_fin, "RETR %s\r\n", file);
	fflush(ctrl_fin);

	/* Data connection established */
	if (ftp_check_response("1") != 0)
		errx(1, "Data connection failed, shouldn't happen");

	flags = O_CREAT | O_WRONLY;
	flags |= (resume) ? O_APPEND : O_TRUNC;

	start_progress_meter(file_sz, &counter);
	retr_file(data_fin, out_fn, flags, &counter);
	stop_progress_meter();

	/* RETR response after the file transfer completion */
	ftp_check_response("2");

	fprintf(ctrl_fin, "QUIT\r\n");
	fflush(ctrl_fin);
	ftp_check_response("2");
	return (200);
}

off_t
ftp_size(const char *fn)
{
	const char	*errstr;
	char		*buf, *s;
	off_t	 	 file_sz;

	fprintf(ctrl_fin, "SIZE %s\r\n", fn);
	fflush(ctrl_fin);
	if ((buf = ftp_response()) == NULL)
		return (0);

	file_sz = 0;
	if (buf[0] == '2') {
		if ((s = strchr(buf, ' ')) != NULL) {
			s++;
			file_sz = strtonum(s, 0, LLONG_MAX, &errstr);
			if (errstr)
				warn("ftp_get: strtonum: %s", errstr);
		}
	}
	free(buf);
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
int
ftp_pasv(void)
{
	struct sockaddr_in	 data_addr;
	char			*buf, *s, *e;
	size_t			 len;
	uint			 addr[4], port[2];
	int			 sock, ret;

	memset(&addr, 0, sizeof(addr));
	memset(&port, 0, sizeof(port));
	fprintf(ctrl_fin, "PASV\r\n");
	fflush(ctrl_fin);
	while ((buf = fparseln(ctrl_fin, &len, NULL, "\0\0\0", 0)) != NULL) {
		if (len != 3 && buf[3] != ' ') { /* Continue till last line */
			free(buf);
			continue;
		}

		if (buf[0] != '2')
			errx(1, "Can't continue without PASV support");

		if ((s = strchr(buf, '(')) == NULL) {
			warnx("Malformed PASV reply");
			return (-1);
		}

		if ((e = strchr(buf, ')')) == NULL) {
			warnx("Malformed PASV reply");
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
		break;
	}

	memset(&data_addr, 0, sizeof(data_addr));
	data_addr.sin_family = AF_INET;
	data_addr.sin_len = sizeof(struct sockaddr_in);
	data_addr.sin_addr.s_addr = htonl(pack4(addr, 0));
	data_addr.sin_port = htons(pack2(port, 0));

	if ((sock = socket(data_addr.sin_family, SOCK_STREAM, 0)) == -1)
		err(1, "ftp_pasv: socket");

	if (connect(sock, (struct sockaddr *)&data_addr,
	    data_addr.sin_len) == -1)
		err(1, "ftp_pasv: connect");

	return (sock);
}

int
ftp_auth(struct url *url)
{
	if (url->user[0] == '\0')
		(void)strlcpy(url->user, "anonymous", sizeof(url->user));

	fprintf(ctrl_fin, "USER %s\r\n", url->user);
	fflush(ctrl_fin);
	if (ftp_check_response("23") != 0)
		return (-1);

	if (url->pass[0])
		fprintf(ctrl_fin, "PASS %s\r\n", url->pass);
	else
		fprintf(ctrl_fin, "PASS\r\n");

	fflush(ctrl_fin);
	if (ftp_check_response("2") != 0)
		return (-1);

	return (0);
}

int
ftp_check_response(const char *res_code)
{
	char	*buf;
	int	 ret;

	ret = -1;
	if ((buf = ftp_response()) == NULL)
		goto exit;

	if (strchr(res_code, buf[0]) == NULL)
		goto exit;

	ret = 0;
exit:
	free(buf);
	return (ret);
}

char *
ftp_response(void)
{
	char		*buf;
	size_t		 len;

	buf = NULL;
	while ((buf = fparseln(ctrl_fin, &len, NULL, "\0\0\0", 0)) != NULL) {
		if (buf[len - 1] == '\r')
			buf[--len] = '\0';

		log_info("%s\n", buf);
		if (len == 3 || buf[3] == ' ')	/* last line */
			break;

		free(buf);
	}

	return (buf);
}
