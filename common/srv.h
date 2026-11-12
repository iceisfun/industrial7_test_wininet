/* srv.h - in-process loopback test servers for the wininet corpus (HTTP, HTTPS over schannel, FTP).
 *
 * Everything binds 127.0.0.1 (and [::1] on the same port) on an ephemeral port. Every wait is bounded, every
 * server has a hard lifetime, srv_stop() joins every thread (<= 3 s). The library resolves ws2_32, sspicli/secur32,
 * crypt32 and ncrypt at run time (GetProcAddress), so nothing here is import-linked: a missing export makes
 * srv_start() return SRV_E_UNAVAILABLE and the test should t_skip().
 *
 * Do not include wininet.h or winhttp.h from here (they conflict with each other); tests include whichever they need.
 * Full documentation: common/SRV.md.  Design rationale and Win10 measurements: docs/research/04_server_and_vm_design.md.
 */
#ifndef SRV_H
#define SRV_H
#include "t.h"
#include <wincrypt.h>

typedef struct srv srv;
typedef struct srv_conn srv_conn;

typedef enum { SRV_HTTP = 0, SRV_HTTPS, SRV_FTP } srv_kind;

/* srv_start return codes */
#define SRV_OK            0
#define SRV_E_UNAVAILABLE 1   /* ws2_32 / sspi / crypt32 / ncrypt export missing (or schannel inbound cred failed) */
#define SRV_E_BIND        2   /* could not bind a loopback port */
#define SRV_E_CERT        3   /* certificate profile could not be created */
#define SRV_E_ARG         4

/* ---------------------------------------------------------------- scripts (HTTP and HTTPS) */
typedef enum {
    SRV_END = 0,      /* end of script (also: terminator when nsteps == 0) -> graceful close */
    SRV_RECV_HEAD,    /* read one request head (to CRLFCRLF or LFLF). Recorded as a request. EOF/error before the
                         first byte ends the connection quietly. data != NULL: expected request-line prefix, a mismatch
                         is recorded as SRV_EV_MISMATCH (the script continues). */
    SRV_RECV_BODY,    /* read the body of the last head: Content-Length or chunked (de-chunked + raw recorded). */
    SRV_RECV_BYTES,   /* read exactly n bytes (n == 0: until EOF); recorded as SRV_EV_BYTES */
    SRV_SEND,         /* send data verbatim (n == 0 -> strlen(data)) */
    SRV_SEND_FMT,     /* send data with %P port, %H Host of last request, %R request-target, %S scheme, %% expanded */
    SRV_SEND_SPLIT,   /* send data in pieces of arg bytes (default 1), sleeping 'flags' ms (default 10) between pieces */
    SRV_SEND_CHUNKED, /* send data as a chunked BODY only (no head): chunks of arg bytes (0 = one chunk), then 0 CRLF CRLF */
    SRV_SEND_PATTERN, /* send n bytes of srv_pattern_byte(i) */
    SRV_REPLY,        /* canned response, see below: status arg, extra headers hdrs (fmt-expanded), body data/n, flags */
    SRV_REPLY_100,    /* send "HTTP/1.1 100 Continue" if the last head had "Expect: 100-continue" (arg != 0: always) */
    SRV_SLEEP,        /* sleep arg ms (capped at 5000; interrupted by srv_stop) */
    SRV_SHUT_WR,      /* shutdown(SD_SEND) (TLS: close_notify first): ends a close-delimited body */
    SRV_RESET,        /* abortive close (RST), ends the script */
    SRV_CLOSE,        /* graceful close, ends the script */
    SRV_LOOP,         /* jump to step arg (keep-alive). At most 1000 jumps per connection. */
    SRV_CALL,         /* fn(conn, step, cfg->user); return < 0 ends the script */
    SRV_AUTH_SSPI,    /* server side SSPI HTTP auth on this connection, package = data ("NTLM" or "Negotiate"):
                         loops recv head -> 401 + WWW-Authenticate token until AcceptSecurityContext completes
                         (max 6 legs), records SRV_EV_AUTH (data = "ok <user>" or "fail 0x<status>"). The next step
                         normally is SRV_REPLY 200. The head that completed auth is the "last request". */
    SRV_CLOSE_IF_ASKED, /* close if the last request had "Connection: close" (HTTP/1.1) or lacked keep-alive (HTTP/1.0) */
} srv_op;

/* SRV_REPLY flags */
#define SRV_R_CHUNKED      0x0001  /* Transfer-Encoding: chunked; chunk size = arg2 (step.n2), 0 = one chunk */
#define SRV_R_CLOSE        0x0002  /* close-delimited: no Content-Length, body then graceful close, script ends */
#define SRV_R_GZIP         0x0004  /* encode the body as gzip (stored deflate blocks) + Content-Encoding: gzip */
#define SRV_R_DEFLATE      0x0008  /* zlib-wrapped deflate (stored) + Content-Encoding: deflate */
#define SRV_R_RAWDEFLATE   0x0010  /* raw deflate (no zlib header) + Content-Encoding: deflate */
#define SRV_R_NO_LENGTH    0x0020  /* no framing header at all (the test supplies it in hdrs, or wants none) */
#define SRV_R_BODY_ON_HEAD 0x0040  /* send the body even if the request was HEAD (malformed-server tests) */
#define SRV_R_HTTP10       0x0080  /* status line says HTTP/1.0 */
#define SRV_R_KEEPALIVE    0x0100  /* add "Connection: Keep-Alive" */
#define SRV_R_CONN_CLOSE   0x0200  /* add "Connection: close" and close after the reply (script ends) */
#define SRV_R_TRUNCATE     0x0400  /* announce the full length but send only half the body, then close */

typedef struct srv_step srv_step;
typedef int (*srv_step_fn)(srv_conn *c, const srv_step *st, void *user);
struct srv_step {
    srv_op op;
    const char *data;  /* bytes / body / expected prefix / package name */
    size_t n;          /* length of data (0 -> strlen when data != NULL); SRV_REPLY with data == NULL: n pattern bytes */
    int arg;           /* status code / chunk size / ms / jump target / piece size */
    const char *hdrs;  /* SRV_REPLY: extra header lines, each ending in \r\n (fmt-expanded like SRV_SEND_FMT) */
    unsigned flags;    /* SRV_REPLY: SRV_R_*;  SRV_SEND_SPLIT: delay ms */
    size_t n2;         /* SRV_REPLY + SRV_R_CHUNKED: chunk size */
    srv_step_fn fn;    /* SRV_CALL */
};
typedef struct { const srv_step *steps; int nsteps; } srv_script;   /* nsteps == 0: run until SRV_END */
#define SRV_SCRIPT(arr) { (arr), (int)(sizeof(arr) / sizeof((arr)[0])) }

/* Step constructors (C99 compound-literal friendly; usable in static initialisers) */
#define S_HEAD()                 { SRV_RECV_HEAD }
#define S_HEAD_EXPECT(prefix)    { SRV_RECV_HEAD, (prefix) }
#define S_BODY()                 { SRV_RECV_BODY }
#define S_BYTES(n_)              { SRV_RECV_BYTES, NULL, (n_) }
#define S_SEND(lit)              { SRV_SEND, (lit), sizeof(lit) - 1 }
#define S_SENDN(p, n_)           { SRV_SEND, (const char *)(p), (n_) }
#define S_FMT(lit)               { SRV_SEND_FMT, (lit) }
#define S_SPLIT(lit, piece, ms)  { SRV_SEND_SPLIT, (lit), sizeof(lit) - 1, (piece), NULL, (ms) }
#define S_CHUNKED(lit, csz)      { SRV_SEND_CHUNKED, (lit), sizeof(lit) - 1, (csz) }
#define S_PATTERN(n_)            { SRV_SEND_PATTERN, NULL, (n_) }
#define S_REPLY(code, hdrs_, body_lit) { SRV_REPLY, (body_lit), sizeof(body_lit) - 1, (code), (hdrs_) }
#define S_REPLYF(code, hdrs_, body_lit, fl) { SRV_REPLY, (body_lit), sizeof(body_lit) - 1, (code), (hdrs_), (fl) }
#define S_REPLYN(code, hdrs_, p, n_, fl)    { SRV_REPLY, (const char *)(p), (n_), (code), (hdrs_), (fl) }
#define S_REPLY_CHUNKED(code, hdrs_, body_lit, csz) { SRV_REPLY, (body_lit), sizeof(body_lit) - 1, (code), (hdrs_), SRV_R_CHUNKED, (csz) }
#define S_REPLY_PATTERN(code, hdrs_, n_, fl) { SRV_REPLY, NULL, (n_), (code), (hdrs_), (fl) }
#define S_100()                  { SRV_REPLY_100 }
#define S_SLEEP(ms)              { SRV_SLEEP, NULL, 0, (ms) }
#define S_SHUTWR()               { SRV_SHUT_WR }
#define S_RESET()                { SRV_RESET }
#define S_CLOSE()                { SRV_CLOSE }
#define S_LOOP()                 { SRV_LOOP, NULL, 0, 0 }
#define S_LOOP_TO(i)             { SRV_LOOP, NULL, 0, (i) }
#define S_CALL(f)                { SRV_CALL, NULL, 0, 0, NULL, 0, 0, (f) }
#define S_AUTH(pkg)              { SRV_AUTH_SSPI, (pkg) }
#define S_CLOSE_IF_ASKED()       { SRV_CLOSE_IF_ASKED }
#define S_END()                  { SRV_END }

/* ---------------------------------------------------------------- FTP */
typedef struct {
    const char *path;   /* absolute, e.g. "/hello.txt" or "/pub/" (trailing '/' or data == NULL && n == -1 marks a dir) */
    const char *data;   /* file content (NULL with n > 0: pattern bytes) */
    long n;             /* size; -1 for a directory */
    const char *mdtm;   /* "YYYYMMDDHHMMSS" (default 20200102030405) */
} srv_ftp_file;
typedef struct {
    const char *cmd_prefix; /* case-insensitive prefix of the command line, e.g. "RETR missing" or "CWD" */
    const char *reply;      /* full reply text (CRLF appended if missing; multi-line allowed). The command is NOT executed. */
    int times;              /* 0 = always, n = only the first n matches */
} srv_ftp_override;
typedef struct {
    const srv_ftp_file *files; int nfiles;
    const srv_ftp_override *overrides; int noverrides;
    const char *banner;     /* default "220 i7 test FTP ready" */
    const char *list_override; /* raw LIST payload instead of the generated one (NLST still generated) */
    int record_pass;        /* 0 (default): PASS recorded as "PASS ***" */
} srv_ftp_config;

/* ---------------------------------------------------------------- server */
/* certificate profiles (HTTPS) */
#define SRV_CERT_LOCALHOST 0  /* CN=localhost, SAN {DNS:localhost, IP:127.0.0.1, IP:::1}, EKU serverAuth, valid now-1d..now+365d */
#define SRV_CERT_CN_OTHER  1  /* CN=i7-other.invalid, no SAN, EKU serverAuth */
#define SRV_CERT_EXPIRED   2  /* as LOCALHOST, valid now-30d..now-1d */
#define SRV_CERT_NO_EKU    3  /* as LOCALHOST without the EKU extension */
#define SRV_CERT_CLIENT    4  /* CN=i7-client, EKU clientAuth: for client-certificate tests (srv_cert_get) */
#define SRV_CERT_COUNT     5

typedef struct {
    srv_kind kind;
    const srv_script *scripts; int nscripts; /* connection i runs scripts[min(i, nscripts-1)]; 0 -> built-in "200 hello" */
    DWORD lifetime_ms;       /* default 20000: after that the server stops accepting and resets live connections */
    DWORD io_timeout_ms;     /* default 5000: SO_RCVTIMEO/SO_SNDTIMEO of each connection */
    int v4_only;             /* 0: also [::1] on the same port (localhost resolves ::1 first, see 04 F2) */
    int cert_profile;        /* HTTPS: SRV_CERT_* */
    DWORD tls_protocols;     /* HTTPS: 0 = schannel default; else SP_PROT_*_SERVER bits to ENABLE (SCH_CREDENTIALS v5) */
    int tls_client_cert;     /* HTTPS: 1 = request a client certificate (ASC_REQ_MUTUAL_AUTH), 2 = also fail without one */
    const srv_ftp_config *ftp; /* FTP */
    void *user;              /* passed to SRV_CALL callbacks */
} srv_config;

int  srv_start(const srv_config *cfg, srv **out);     /* SRV_OK: accepting on return */
void srv_stop(srv *s);                                 /* joins everything, frees s; NULL ok; <= ~3 s */
unsigned short srv_port(const srv *s);
int  srv_has_v6(const srv *s);
/* "http[s]|ftp://127.0.0.1:<port><path>" in one of 8 rotating per-server buffers */
const char *srv_url(srv *s, const char *path);
const char *srv_url_host(srv *s, const char *host, const char *path); /* host e.g. "localhost" or "[::1]" */
const char *srv_hostport(srv *s);                      /* "127.0.0.1:<port>" */
/* Convenience: one HTTP server with a single script (or the built-in one when steps == NULL). */
srv *srv_http(const srv_step *steps, int nsteps);
srv *srv_https(const srv_step *steps, int nsteps, int cert_profile);
const char *srv_strerror(int rc);
int  srv_last_error(void);                            /* rc of the last srv_start in this process (for srv_http/srv_https NULL) */

/* ---------------------------------------------------------------- wire recorder */
typedef enum {
    SRV_EV_ACCEPT = 1, SRV_EV_HEAD, SRV_EV_BODY, SRV_EV_BYTES, SRV_EV_EOF, SRV_EV_RESET, SRV_EV_TIMEOUT, SRV_EV_ERROR,
    SRV_EV_TLS_DONE,     /* data: "proto=0x.. cipher=0x.. suite=0x.. client_cert=0|1" */
    SRV_EV_TLS_ABORT,    /* client gave up during the handshake (normal for cert errors, see 04 F11); data: reason */
    SRV_EV_SCRIPT_DONE, SRV_EV_MISMATCH, SRV_EV_FTP_CMD, SRV_EV_FTP_DATA, SRV_EV_AUTH, SRV_EV_SENT, SRV_EV_CLOSED,
    SRV_EV_HS_BYTES,     /* first bytes of a TLS handshake read from the client (flake12030 probe); data: byte count */
    SRV_EV_ANY = 0
} srv_ev_kind;
typedef struct {
    srv_ev_kind kind;
    int conn;            /* connection index (accept order, 0-based) */
    int req;             /* request index for HEAD/BODY events, else -1 */
    const char *data;    /* event bytes (NUL-terminated copy), may be NULL */
    size_t n;
    DWORD t_ms;          /* ms since srv_start */
} srv_event;
/* Wait until at least count events of kind (SRV_EV_ANY: any) exist. 1 = reached, 0 = timed out. */
int  srv_wait_events(srv *s, srv_ev_kind kind, int count, DWORD timeout_ms);
int  srv_count_events(srv *s, srv_ev_kind kind);
int  srv_events(srv *s, const srv_event **ev);         /* snapshot (valid until srv_stop); returns count */
const char *srv_event_kind_name(srv_ev_kind k);
int  srv_conn_count(srv *s);                           /* connections accepted so far */
void srv_dump(srv *s);                                 /* t_note every event (debugging aid) */

/* Parsed view of request i (arrival order across all connections); NULL / -1 when out of range */
int  srv_req_count(srv *s);
int  srv_wait_requests(srv *s, int count, DWORD timeout_ms);
int  srv_req_conn(srv *s, int i);                      /* connection that carried request i */
const char *srv_req_line(srv *s, int i);               /* "GET /p HTTP/1.1" (no CRLF) */
const char *srv_req_method(srv *s, int i);
const char *srv_req_target(srv *s, int i);             /* request-target as sent ("/p?q", or absolute form via proxy) */
int  srv_req_header_count(srv *s, int i);
const char *srv_req_header_name(srv *s, int i, int h); /* exact casing as sent */
const char *srv_req_header_value(srv *s, int i, int h);/* leading/trailing whitespace trimmed */
const char *srv_req_header(srv *s, int i, const char *name);     /* case-insensitive, first match */
int  srv_req_header_index(srv *s, int i, const char *name);      /* position in send order, -1 if absent */
int  srv_req_header_occurrences(srv *s, int i, const char *name);
const char *srv_req_head_raw(srv *s, int i, size_t *n); /* head bytes exactly as received (incl. final CRLFCRLF) */
const char *srv_req_body(srv *s, int i, size_t *n);    /* de-chunked; NULL if the script did not read a body */
const char *srv_req_body_raw(srv *s, int i, size_t *n);/* body bytes as sent (chunk framing included) */
int  srv_req_body_chunked(srv *s, int i);

/* FTP state after/while running */
const char *srv_ftp_file_data(srv *s, const char *path, long *n); /* current content (uploaded or initial); NULL if absent */
int  srv_ftp_cmd_count(srv *s);
const char *srv_ftp_cmd(srv *s, int i);                /* command line i ("USER anonymous"), PASS masked unless record_pass */

/* ---------------------------------------------------------------- helpers usable from SRV_CALL */
int  srv_conn_id(srv_conn *c);
srv *srv_conn_server(srv_conn *c);
int  srv_conn_send(srv_conn *c, const void *p, size_t n);   /* 0 ok */
int  srv_conn_sendf(srv_conn *c, const char *fmt, ...);
int  srv_conn_recv_head(srv_conn *c);                        /* request index, or -1 on EOF/error */
int  srv_conn_last_req(srv_conn *c);

/* ---------------------------------------------------------------- data helpers */
static inline unsigned char srv_pattern_byte(size_t i) { return (unsigned char)('a' + (i * 7 + i / 26) % 26); }
int  srv_pattern_check(const void *p, size_t n, size_t offset);   /* 1 if p matches the pattern at offset */
unsigned long srv_crc32(const void *p, size_t n);
/* encoders: malloc'd result (free()), *outn length. mode 0 = gzip, 1 = zlib, 2 = raw deflate (all stored blocks) */
unsigned char *srv_deflate_stored(const void *p, size_t n, int mode, size_t *outn);
char *srv_b64(const void *p, size_t n);                 /* malloc'd */
unsigned char *srv_unb64(const char *s, size_t *n);     /* malloc'd; NULL on bad input */
/* Precompressed (real Huffman) gzip / zlib / raw-deflate of SRV_FOX_TEXT repeated 20 times (900 bytes). */
#define SRV_FOX_TEXT "The quick brown fox jumps over the lazy dog.\n"
#define SRV_FOX_LEN  900
extern const unsigned char srv_fox_gzip[];   extern const size_t srv_fox_gzip_len;
extern const unsigned char srv_fox_zlib[];   extern const size_t srv_fox_zlib_len;
extern const unsigned char srv_fox_raw[];    extern const size_t srv_fox_raw_len;
const char *srv_fox_text(void);              /* the 900 plain bytes, NUL-terminated */

/* HTTPS certificate of a profile (created lazily, cached for the process, keys deleted at exit). Do not free. */
PCCERT_CONTEXT srv_cert_get(int profile);
#endif
