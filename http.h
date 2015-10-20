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

struct http_hdrs {
	char	location[BUFSIZ];	/* Redirect Location */
	off_t	c_len;			/* Content-Length */
};

struct url {
	char	 host[HOST_NAME_MAX+1];
	char	 port[NI_MAXSERV];
	char	 basic_auth[BUFSIZ];
	char	*path;
	int	 scheme;
};

/* main.c */
extern const char	*ua;
extern int		 verbose;

/* http.c */
int	 http_connect(struct url *, struct url *);
char	*http_parseln(FILE *, size_t *);
int	 proxy_connect(FILE *, struct url *, struct url *);
int	 http_get(off_t, struct url *, struct http_hdrs *);
void	 http_retr(const char *, off_t, off_t);

/* util.c */
extern int	 ftp_debug;
int		 tcp_connect(const char *, const char *);
int		 header_insert(struct http_hdrs *, const char *);
void		 log_info(const char *, ...)
		    __attribute__((__format__ (printf, 1, 2)))
		    __attribute__((__nonnull__  (1)));
void		 send_cmd(FILE *, const char *, ...)
		    __attribute__((__format__ (printf, 2, 3)))
		    __attribute__((__nonnull__ (2)));
void		 vsend_cmd(FILE *, const char *, va_list);
void		 log_request(struct url *, struct url *);
void		 retr_file(FILE *, const char *, off_t, off_t);
int		 http_response_code(char *);
char		*url_encode(const char *);
const char	*http_errstr(int);
const char	*base64_encode(const char *, const char *);

#ifndef SMALL
/* main.c */
extern char	*tls_options;

/* https.c */
int	https_connect(struct url *, struct url *);
int	https_get(off_t, struct url *, struct http_hdrs *);
void	https_retr(const char *, off_t, off_t);

/* ftp.c */
int	ftp_connect(struct url *, struct url *);
int	ftp_get(off_t, struct url *);
void	ftp_command(void);
void	ftp_retr(const char *, off_t);
#endif

