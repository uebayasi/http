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

#define	TMPBUF_LEN	131072

#define	HTTP	1
#define HTTPS	2
#define FTP	3
#define UNDEF	4

struct headers {
	char	location[BUFSIZ];	/* Redirect Location */
	off_t	c_len;			/* Content-Length */
};

/* http://<user>:<pass>@<host>:<port>/<path> */
struct url {
	char	host[HOST_NAME_MAX+1];
	char	port[16];
	char	user[LOGIN_NAME_MAX];
	char	pass[256];
	char	path[BUFSIZ];
	int	proto;
};

struct proto {
	int (*connect)(struct url *, struct url *);
	int (*get)(struct url *, const char *, int, struct headers *);
};

/* http.c */
int		 http_connect(struct url *, struct url *);
int		 http_response_code(char *);

#ifndef SMALL
/* cookie.c */
void	cookie_load(void);
void	cookie_get(const char *, const char *, int, char **);
#endif

/* util.c */
int		 tcp_connect(const char *, const char *);
int		 header_insert(struct headers *, const char *);
void		 log_info(const char *, ...);
void		 log_request(struct url *, struct url *);
char		*url_encode(const char *);
int		 url_parse(const char *, struct url *, int);
const char	*errstr(int);
const char	*base64_encode(const char *, const char *);

