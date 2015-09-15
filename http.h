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

struct headers {
	char	location[BUFSIZ];	/* Redirect Location */
	off_t	c_len;			/* Content-Length */
};

struct url {
	char	host[HOST_NAME_MAX+1];
	char	port[NI_MAXSERV];
	char	user[LOGIN_NAME_MAX];
	char	pass[256];
	char	path[BUFSIZ];
	int	proto;
};

/* http.c */
int	 http_connect(struct url *, struct url *);
int	 proxy_connect(FILE *, struct url *, struct url *);
int	 http_get(const char *, off_t, struct url *, struct headers *);

/* util.c */
int		 tcp_connect(const char *, const char *);
int		 header_insert(struct headers *, const char *);
void		 log_info(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__  (1)));
void		 send_cmd(const char *, FILE *, const char *, ...)
    __attribute__((__format__ (printf, 3, 4)))
    __attribute__((__nonnull__ (3)));
void		 vsend_cmd(const char *, FILE *, const char *, va_list);
void		 log_request(struct url *, struct url *);
void	 	 retr_file(FILE *, const char *, off_t, off_t);
int		 http_response_code(char *);
char		*url_encode(const char *);
void		 url_parse(const char *, struct url *);
const char	*http_errstr(int);
const char	*base64_encode(const char *, const char *);

#ifndef SMALL
/* https.c */
int	https_connect(struct url *, struct url *);
int	https_get(const char *, off_t, struct url *, struct headers *);

/* ftp.c */
int	ftp_connect(struct url *, struct url *);
int	ftp_get(const char *, off_t, struct url *, struct headers *);
#endif

