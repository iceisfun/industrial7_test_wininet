/* srv_int.h - private to common/srv_*.c */
#ifndef SRV_INT_H
#define SRV_INT_H
#include "srv.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS 1
#include <sspi.h>
#include <schannel.h>
#include <ncrypt.h>
#include <stdlib.h>
#include <ctype.h>

/* ---- runtime-resolved APIs (nothing here is import-linked) ---- */
#define SRV_WS_FUNCS(X) X(WSAStartup) X(socket) X(bind) X(listen) X(accept) X(connect) X(recv) X(send) \
    X(closesocket) X(shutdown) X(select) X(setsockopt) X(getsockname) X(ioctlsocket) X(WSAGetLastError)
#define SRV_CRYPT_FUNCS(X) X(CertStrToNameW) X(CryptEncodeObject) X(CertCreateSelfSignCertificate) \
    X(CertFreeCertificateContext) X(CertGetCertificateContextProperty)
#define SRV_NCRYPT_FUNCS(X) X(NCryptOpenStorageProvider) X(NCryptCreatePersistedKey) X(NCryptSetProperty) \
    X(NCryptFinalizeKey) X(NCryptFreeObject) X(NCryptOpenKey) X(NCryptDeleteKey)
#define SRV_DECL(f) __typeof__(&f) f;
typedef struct { int tried, ok; SRV_WS_FUNCS(SRV_DECL) } srv_ws_api;
typedef struct { int tried, ok; SRV_CRYPT_FUNCS(SRV_DECL) } srv_crypt_api;
typedef struct { int tried, ok; SRV_NCRYPT_FUNCS(SRV_DECL) } srv_ncrypt_api;
extern srv_ws_api SWS;
extern srv_crypt_api SCR;
extern srv_ncrypt_api SNC;
extern PSecurityFunctionTableW SSP;   /* via InitSecurityInterfaceW (sspicli.dll, then secur32.dll) */
int srv_ws_load(void);
int srv_sspi_load(void);
int srv_crypt_load(void);

static inline unsigned short srv_htons(unsigned short v) { return (unsigned short)((v >> 8) | (v << 8)); }

/* ---- recorder / requests ---- */
typedef struct {
    int conn;
    char *head; size_t nhead;
    char *line, *method, *target;
    int nh; char **hn; char **hv;
    char *body; size_t nbody; char *body_raw; size_t nbody_raw; int chunked, has_body;
} srv_req;

#define SRV_MAXCONN 64
struct srv_conn {
    srv *s; int id; SOCKET sock; HANDLE thr; volatile LONG done;
    const srv_script *sc;
    /* plaintext input buffer */
    char *in; size_t nin, capin;
    int eof;            /* peer closed (plaintext level) */
    int last_req;       /* -1 none */
    /* TLS */
    int tls; CtxtHandle ctx; int have_ctx; SecPkgContext_StreamSizes sz;
    char *raw; size_t nraw, capraw;
    int closed_notify;
    char *extra_hdr;    /* pending header lines for the next SRV_REPLY (e.g. final Negotiate token) */
    /* FTP */
    void *ftp;
};

typedef struct srv_ftp_state srv_ftp_state;

struct srv {
    srv_config cfg;
    srv_kind kind;
    SOCKET l4, l6; int v6; unsigned short port;
    HANDLE accept_thr, stop_ev; volatile LONG stop;
    DWORD t0;
    CRITICAL_SECTION cs;
    srv_conn *conns[SRV_MAXCONN]; int nconn;
    srv_event *ev; int nev, capev;
    srv_req **req; int nreq, capreq;
    void **keep; int nkeep, capkeep;      /* allocations freed at stop (snapshots) */
    char url[8][300]; LONG urli; char hp[64];
    /* TLS */
    CredHandle cred; int have_cred;
    /* FTP */
    srv_ftp_state *ftp;
    char **ftpcmd; int nftpcmd, capftpcmd;
};

void srv_record(srv *s, srv_ev_kind k, int conn, int req, const void *data, size_t n);
void srv_recordf(srv *s, srv_ev_kind k, int conn, const char *fmt, ...);
int  srv_add_req(srv *s, srv_req *r);       /* returns index */
srv_req *srv_get_req(srv *s, int i);
void srv_keep(srv *s, void *p);

/* connection IO (plaintext, TLS-aware) */
int  srv_io_send(srv_conn *c, const void *p, size_t n);       /* 0 ok, -1 error */
int  srv_io_fill(srv_conn *c);                                /* >0 bytes added, 0 EOF, -1 error */
void srv_io_consume(srv_conn *c, size_t n);
void srv_io_reserve(srv_conn *c, size_t more);
int  srv_tls_send(srv_conn *c, const void *p, size_t n);
int  srv_tls_fill(srv_conn *c);
int  srv_raw_recv(srv_conn *c, char *p, int n);               /* records RESET/TIMEOUT/ERROR; returns recv() result */
int  srv_wait_stop(srv *s, DWORD ms);                         /* 1 if stopping */
void srv_set_timeouts(SOCKET so, DWORD ms);

/* per-kind connection handlers */
void srv_http_conn(srv_conn *c);
int  srv_tls_accept(srv_conn *c);                             /* 0 ok */
void srv_tls_shutdown(srv_conn *c);
void srv_tls_free(srv_conn *c);
int  srv_tls_cred(srv *s);                                    /* 0 ok, else SRV_E_* */
void srv_tls_cred_free(srv *s);
void srv_ftp_conn(srv_conn *c);
int  srv_ftp_init(srv *s);
void srv_ftp_free(srv *s);
SOCKET srv_listen_v4(unsigned short *port);
SOCKET srv_accept_bounded(srv *s, SOCKET *ls, int nls, DWORD ms);
#endif
