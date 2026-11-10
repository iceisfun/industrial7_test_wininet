/* tls_util.h - helpers for the https_tls area (prefix tls_).
 *
 * Everything runs against servers this exe starts on 127.0.0.1:
 *   - the shared schannel HTTPS server (common/srv.h, srv_https / srv_start with SRV_HTTPS);
 *   - a raw "ClientHello observer" (tls_hello_*): plain winsock, reads the client's first TLS flight, parses
 *     version / cipher suites / SNI / ALPN / supported_versions, then answers with a scripted reaction
 *     (close, reset, alert, plaintext, garbage). No schannel needed;
 *   - a CONNECT tunnel proxy (tls_proxy_*): plain winsock, records the CONNECT head, answers with a scripted
 *     status, and on 200 relays bytes to a target loopback port.
 * Nothing touches the internet, the registry or proxy settings (sessions are DIRECT or per-session PROXY).
 */
#ifndef TLS_UTIL_H
#define TLS_UTIL_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

/* Options / structs missing from the mingw headers (values from the Win10 SDK and the decomp). */
#ifndef INTERNET_OPTION_SECURITY_CONNECTION_INFO
#define INTERNET_OPTION_SECURITY_CONNECTION_INFO 66
#endif
#ifndef SECPKGCONTEXT_CIPHERINFO_V1
#define SECPKGCONTEXT_CIPHERINFO_V1 1
#endif
typedef struct {
    DWORD dwProtocol; DWORD aiCipher; DWORD dwCipherStrength; DWORD aiHash; DWORD dwHashStrength; DWORD aiExch; DWORD dwExchStrength;
} tls_conn_info;            /* SecPkgContext_ConnectionInfo (28 bytes) */
typedef struct {
    DWORD dwVersion, dwProtocol, dwCipherSuite, dwBaseCipherSuite;
    WCHAR szCipherSuite[64], szCipher[64];
    DWORD dwCipherLen, dwCipherBlockLen;
    WCHAR szHash[64];
    DWORD dwHashLen;
    WCHAR szExchange[64];
    DWORD dwMinExchangeLen, dwMaxExchangeLen;
    WCHAR szCertificate[64];
    DWORD dwKeyType;
} tls_cipher_info;          /* SecPkgContext_CipherInfo (680 bytes) */
typedef struct {
    DWORD dwSize;
    BOOL fSecure;
    tls_conn_info connectionInfo;
    tls_cipher_info cipherInfo;
} tls_sec_conn_info;        /* INTERNET_SECURITY_CONNECTION_INFO: 0x2CC = 716 bytes on x64 (decomp case 0x42) */

#define TLS_SP_TLS1_0_SERVER 0x40
#define TLS_SP_TLS1_1_SERVER 0x100
#define TLS_SP_TLS1_2_SERVER 0x400
#define TLS_SP_TLS1_3_SERVER 0x1000
#define TLS_SP_TLS1_2_CLIENT 0x800

/* ------------------------------------------------------------------ wininet request bundle */
typedef struct { HINTERNET hi, hc, hr; } treq;
/* session (DIRECT, 5 s timeouts, or proxy != NULL: INTERNET_OPEN_TYPE_PROXY), connect, open request.
 * flags are HttpOpenRequest flags (INTERNET_FLAG_SECURE is NOT added automatically). 1 = all handles valid. */
int   treq_open(treq *t, const char *host, unsigned short port, const char *verb, const char *path, DWORD flags);
int   treq_open_proxy(treq *t, const char *proxy, const char *host, unsigned short port, const char *path, DWORD flags);
void  treq_close(treq *t);
DWORD treq_send(treq *t);                       /* 0 on success, else GetLastError() */
DWORD treq_status(treq *t);                     /* HTTP status (0 if not available) */
size_t treq_body(treq *t, char *buf, size_t cap);
DWORD tls_secflags(HINTERNET h);                /* INTERNET_OPTION_SECURITY_FLAGS (0xDEADBEEF if the query fails) */
int   tls_set_secflags(HINTERNET h, DWORD v);   /* plain set (no OR) */

/* One full request on a fresh session: returns 0 or the error; *status = HTTP status. */
DWORD tls_try(srv *s, const char *host, DWORD secflags, DWORD openflags, DWORD *status);

/* HTTPS server helpers (NULL -> caller must t_skip with srv_strerror(srv_last_error())) */
srv  *tls_srv(int profile, const srv_step *st, int nsteps);
srv  *tls_srv_cfg(int profile, DWORD protocols, int client_cert, const srv_step *st, int nsteps, int *rc);
/* data of the first TLS_DONE event ("proto=0x.. cipher=.. suite=..") or NULL */
const char *tls_done_data(srv *s, int idx);
int   tls_count(srv *s, srv_ev_kind k);
void  tls_dump_tls_events(srv *s);
/* hex value after "key=" in a TLS_DONE data string; 0xFFFFFFFF if absent */
DWORD tls_ev_field(const char *data, const char *key);

#define TLS_SKIP_SRV() do { t_skip("HTTPS server unavailable: %s", srv_strerror(srv_last_error())); return; } while (0)

/* ------------------------------------------------------------------ raw ClientHello observer */
enum { TH_CLOSE = 0, TH_RESET, TH_ALERT, TH_PLAINTEXT_HTTP, TH_GARBAGE, TH_SILENT_CLOSE_NOREAD, TH_HANGUP_AFTER_SH };
#define TH_MAX_CONN 8
typedef struct {
    int complete;              /* a full ClientHello was parsed */
    int rec_type, rec_ver;     /* record header */
    int hs_type, client_ver;   /* handshake type (1) and legacy_version */
    int ncipher;               /* cipher suites offered */
    unsigned short ciphers[128];
    int nexts; unsigned short exts[64];  /* extension types in order */
    char sni[256]; int has_sni;
    char alpn[256]; int has_alpn;        /* comma-joined protocol names */
    int nver; unsigned short versions[16]; /* supported_versions */
    int has_ems, has_reneg_info, has_status_request, has_sigalgs;
    size_t nbytes;
} th_hello;
typedef struct th_srv th_srv;
th_srv *th_start(int reaction);               /* NULL if winsock unavailable */
unsigned short th_port(th_srv *t);
int    th_wait(th_srv *t, int nconn, DWORD ms); /* wait for nconn parsed hellos (or connections ended) */
int    th_count(th_srv *t);                    /* connections seen */
const th_hello *th_get(th_srv *t, int i);
void   th_stop(th_srv *t);
int    th_has_ext(const th_hello *h, unsigned short type);

/* ------------------------------------------------------------------ CONNECT proxy */
typedef struct tp_srv tp_srv;
/* reply: full raw response sent to the CONNECT ("HTTP/1.1 200 Connection established\r\n\r\n");
 * when it starts with "HTTP/1.x 200", bytes are then relayed to 127.0.0.1:target_port. */
tp_srv *tp_start(const char *reply, unsigned short target_port);
unsigned short tp_port(tp_srv *p);
int    tp_wait(tp_srv *p, int n, DWORD ms);
int    tp_count(tp_srv *p);
const char *tp_head(tp_srv *p, int i);        /* CONNECT head as received (NUL-terminated) */
void   tp_stop(tp_srv *p);

/* ------------------------------------------------------------------ misc */
int  tls_ws_ok(void);                          /* ws2_32 resolved + WSAStartup done */
const char *tls_hostport(const char *host, unsigned short port);  /* rotating buffer */
#endif
