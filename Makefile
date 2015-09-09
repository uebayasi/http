# Define SMALL to disable https and ftp support
.if defined(SMALL)
CFLAGS+=	-DSMALL 
.endif

PROG=		http
MAN=		http.1
DEBUG=		-g -Wall -O0
SRCS=		main.c http.c util.c progressmeter.c
LDADD+=		-lutil
DPADD+= 	${LIBUTIL}

.ifndef SMALL
SRCS+=		ftp.c https.c
LDADD+=		-ltls -lssl -lcrypto
DPADD+=		${LIBTLS} ${LIBSSL} ${LIBCRYPTO}
.endif

.include <bsd.prog.mk>
