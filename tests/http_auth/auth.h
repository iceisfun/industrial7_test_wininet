/* http_auth - shared helpers for the authentication area (prefix auth_).
 * Every peer is an in-process loopback server (common/srv.h); no internet, no system-wide state.
 * VM_TIMEOUT: 300 */
#ifndef HTTP_AUTH_H
#define HTTP_AUTH_H
#include "t.h"
#include <winsock2.h>
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

#define START_OR_SKIP(cfgp, sp) do { int rc_ = srv_start((cfgp), (sp)); if (rc_) { t_skip("server unavailable: %s", srv_strerror(rc_)); return; } } while (0)
#define SRV_OR_SKIP(s) do { if (!(s)) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; } } while (0)

/* ------------------------------------------------------------------ hashing (MD5, MD4, HMAC-MD5) */
void a_md5(const void *p, size_t n, unsigned char out[16]);
void a_md4(const void *p, size_t n, unsigned char out[16]);
void a_hmac_md5(const void *key, size_t kn, const void *p, size_t n, unsigned char out[16]);
void a_hex(const unsigned char *p, size_t n, char *out);        /* lowercase, NUL-terminated */
void a_md5_hex(const char *s, char out[33]);                     /* md5 of a C string, lowercase hex */
char *a_b64s(const char *s);                                      /* srv_b64 of a C string (malloc'd) */

/* "Basic " + base64(user:pass) in a rotating static buffer */
const char *a_basic(const char *user, const char *pass);

/* Parse one auth-param out of a header value ("Digest a=\"x\", b=y"). Returns 1 if found. */
int a_param(const char *hv, const char *name, char *out, size_t cap);
/* Number of comma-separated auth-params in a Digest header (top level, quotes respected). */
int a_param_count(const char *hv);

/* RFC 2617 digest response. qop NULL/"" => RFC 2069 form. sess => MD5-sess HA1. */
void a_digest_response(const char *user, const char *realm, const char *pass, const char *method, const char *uri,
                       const char *nonce, const char *nc, const char *cnonce, const char *qop, int sess, char out[33]);

/* ------------------------------------------------------------------ gate server (SRV_CALL) */
/* A keep-alive server connection that answers every request:
 *   accepted credential header  -> 200 ok_body
 *   anything else               -> code (401/407) + challenge + deny_body
 * The header checked is Authorization for 401 and Proxy-Authorization for 407. */
typedef struct gate gate;
struct gate {
    int code;                    /* 401 (default) or 407 */
    const char *challenge;       /* header lines of the challenge reply (each ending CRLF) */
    const char *accept[4];       /* exact header values accepted (NULL-terminated list) */
    int (*verify)(gate *g, srv *s, int ri, const char *hv);   /* optional; nonzero = accept */
    const char *ok_body, *deny_body;
    const char *ok_hdrs;         /* extra header lines on the 200 */
    int close_on_deny;           /* add Connection: close to the challenge and close */
    int close_on_ok;
    int deny_403_after;          /* >0: after this many denials answer 403 instead (loop guard) */
    /* digest verifier inputs */
    const char *user, *pass, *realm, *nonce;
    int sess;
    /* NTLM custom server */
    int ntlm_mode;               /* 0 = none; 1 = NTLM; 2 = Negotiate wrapper is not supported (NTLM only) */
    unsigned char ntlm_type3[2048]; size_t ntlm_type3_len; unsigned ntlm_type1_flags;
    char ntlm_user[128], ntlm_domain[128], ntlm_ws[128];
    int ntlm_v2_ok;              /* NTProofStr matched with pass */
    /* counters (written by the server threads) */
    volatile LONG n_ok, n_deny, n_req;
};
int gate_fn(srv_conn *c, const srv_step *st, void *user);
/* Start an HTTP server whose every connection runs gate_fn with g. NULL on failure (t_skip done by caller). */
srv *gate_start(gate *g);
srv *gate_start_kind(gate *g, int kind);   /* SRV_HTTP or SRV_HTTPS (SRV_CERT_LOCALHOST) */

/* Digest helpers (digest.c): verify callback (accepts a response computed with g->user/pass/realm/nonce/sess),
 * recomputation of the recorded header of request i, and a gate preset (realm "i7digest", fixed nonce). */
int digest_verify(gate *g, srv *s, int ri, const char *hv);
int digest_check_recorded(srv *s, int i, const char *user, const char *realm, const char *pass, int sess, const char *want_qop);
void dgate(gate *g, const char *challenge, const char *user, const char *pass);

/* ------------------------------------------------------------------ client helper */
typedef struct {
    const char *verb, *path, *hdrs;
    const char *cuser, *cpass;   /* InternetConnectA user / password */
    const char *ruser, *rpass;   /* INTERNET_OPTION_USERNAME / PASSWORD on the request handle (NULL = not set) */
    const char *puser, *ppass;   /* INTERNET_OPTION_PROXY_USERNAME / PASSWORD on the request handle */
    DWORD flags;                 /* 0 -> T_INET_FRESH */
    int no_flags;                /* flags really 0 */
    const char *body; DWORD body_len;
} areq;
typedef struct {
    BOOL ok; DWORD err; DWORD status;
    char body[1024]; size_t n;
    HINTERNET hr;                /* left open when keep != 0 */
} ares;
/* Opens a request on hc (an existing connect handle), applies options, sends, reads status + body.
 * keep = leave the request handle open in r->hr. */
void a_send(HINTERNET hc, const areq *q, ares *r, int keep);
/* Opens session + connect to s (InternetConnect with q->cuser/cpass), runs a_send, closes everything. */
void a_once(srv *s, const areq *q, ares *r);
HINTERNET a_connect(HINTERNET hi, srv *s, const char *user, const char *pass);
DWORD a_status(HINTERNET hr);
/* HttpQueryInfoA string with index; returns 1 if ok. */
int a_query(HINTERNET hr, DWORD what, DWORD *index, char *buf, DWORD cap);
/* Query an option string (A). Returns 1 if ok; len = returned length. */
int a_qopt(HINTERNET h, DWORD opt, char *buf, DWORD cap, DWORD *len);
void a_close(HINTERNET h);
/* Authorization header of request i (NULL if none), and Proxy-Authorization */
#define REQ_AUTH(s, i)  srv_req_header((s), (i), "Authorization")
#define REQ_PAUTH(s, i) srv_req_header((s), (i), "Proxy-Authorization")
void a_dump(srv *s);
/* srv_stop with a NOTE when stopping takes long (keeps the area inside its VM time budget) */
void a_srv_stop(srv *s);
#define srv_stop(s) a_srv_stop(s)   /* t_note request lines + auth headers */
#endif
