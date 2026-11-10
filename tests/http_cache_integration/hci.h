/* hci.h - helpers for the http_cache_integration area (prefix hci_).
 *
 * Every test starts its own loopback server (common/srv.h). Cache URLs are
 *   http://127.0.0.1:<ephemeral port>/<wininet_<pid>_<n>_tag>
 * and are registered with t_cache_track (deleted at cleanup/exit). The "plan" server answers request k (arrival order
 * across all connections) with reply[min(k, n-1)], or with the conditional reply when the request carries
 * If-None-Match / If-Modified-Since and the plan has one. Nothing here touches the internet.
 */
#ifndef HCI_H
#define HCI_H
#include "t.h"
#include <winsock2.h>
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

#ifndef INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ
#define INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ 122
#endif
#ifndef REDIRECT_CACHE_ENTRY
#define REDIRECT_CACHE_ENTRY 0x00000800
#endif

/* ---------------------------------------------------------------- plan server */
#define HCI_MAXR 8
typedef struct {
    int status;              /* 0 -> 200 */
    char hdrs[768];          /* header lines, each ending in CRLF (no framing headers) */
    const void *body; size_t len; /* body bytes (len 0 with body != NULL -> strlen) */
    int no_length;           /* 1: no Content-Length (close-delimited, connection closed after) */
    int close;               /* 1: add Connection: close and close */
} hci_reply;
typedef struct {
    hci_reply r[HCI_MAXR]; int n;
    hci_reply cond; int has_cond;  /* answer for conditional requests */
    volatile LONG served;          /* replies sent */
    volatile LONG cond_served;
} hci_plan;

int  hci_wait_request(srv_conn *c);               /* 0: server stopping (hci_wait.c) */
srv *hci_plan_start(hci_plan *p);                  /* NULL -> t_skip already called by the caller (check) */
#define HCI_START(p, s) do { (s) = hci_plan_start(p); if (!(s)) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; } } while (0)
/* set reply i: hdrs printf-style */
hci_reply *hci_set(hci_plan *p, int i, int status, const char *body, const char *hdrfmt, ...);
hci_reply *hci_set_cond(hci_plan *p, int status, const char *hdrfmt, ...);

/* ---------------------------------------------------------------- names and times */
const char *hci_url(srv *s, const char *tag);      /* unique URL on s, registered for cache deletion (rotating buffers) */
const char *hci_url_ext(srv *s, const char *tag, const char *ext); /* same, path ends in ".ext" */
void hci_http_date(char *out, size_t cap, LONGLONG offset_sec);  /* RFC 1123 date for now+offset (guest clock) */
LONGLONG hci_ft_now(void);                          /* FILETIME now as 100 ns ticks */
LONGLONG hci_ft(FILETIME f);
#define HCI_SEC 10000000LL
#define HCI_DAY (86400LL * HCI_SEC)

/* ---------------------------------------------------------------- client */
typedef struct {
    int ok;                  /* handle obtained */
    DWORD err;               /* GetLastError when !ok */
    int status;              /* HTTP status (0 if query failed) */
    DWORD reqflags; int reqflags_ok;     /* INTERNET_OPTION_REQUEST_FLAGS after send */
    char body[16384]; size_t len; int read_ok;
    char datafile[MAX_PATH + 1]; DWORD datafile_err;    /* DATAFILE_NAME queried after reading, before close */
    char datafile_early[MAX_PATH + 1]; DWORD datafile_early_err; /* queried right after send, before reading */
    char rawhdrs[4096];      /* HTTP_QUERY_RAW_HEADERS_CRLF */
    char url_opt[1024];      /* INTERNET_OPTION_URL */
} hci_resp;

/* InternetOpenUrlA(url, hdrs, flags), read everything into r. Returns r->status. */
int hci_get(HINTERNET hi, const char *url, const char *hdrs, DWORD flags, hci_resp *r);
/* Connect + HttpOpenRequestA(verb, path of url) + optional setup(hreq, ctx) + HttpSendRequestA(hdrs, body) + read. */
typedef void (*hci_setup_fn)(HINTERNET hreq, void *ctx);
int hci_req(HINTERNET hi, srv *s, const char *verb, const char *url, DWORD flags, const char *hdrs,
            const void *body, DWORD blen, hci_setup_fn setup, void *ctx, hci_resp *r);
#define hci_from_cache(r) ((r)->reqflags_ok && ((r)->reqflags & INTERNET_REQFLAG_FROM_CACHE))

/* default session: DIRECT, 5 s timeouts */
HINTERNET hci_open(void);

/* ---------------------------------------------------------------- cache */
INTERNET_CACHE_ENTRY_INFOA *hci_info(const char *url, DWORD *err);  /* malloc'd or NULL (*err) */
int  hci_exists(const char *url);
int  hci_file_read(const char *path, char *buf, size_t cap, size_t *n); /* 1 ok */
int  hci_file_exists(const char *path);
int  hci_hdr_has(const INTERNET_CACHE_ENTRY_INFOA *e, const char *needle); /* substring of lpHeaderInfo, case-insensitive */
const char *hci_ext_of(const INTERNET_CACHE_ENTRY_INFOA *e);       /* lpszFileExtension or "" */
const char *hci_local_ext(const INTERNET_CACHE_ENTRY_INFOA *e);    /* extension of lpszLocalFileName ("" if none), no dot */
void hci_note_entry(const char *what, const INTERNET_CACHE_ENTRY_INFOA *e);
BOOL hci_delete(const char *url);
/* wait until the server saw n requests (short, bounded) then return the count */
int  hci_reqs(srv *s, int n);

/* ---------------------------------------------------------------- pass-2 helpers */
/* one GET on a fresh session (flags, optional request headers), then the entry info (malloc'd or NULL) */
INTERNET_CACHE_ENTRY_INFOA *hci_fetch(const char *url, const char *hdrs, DWORD flags, hci_resp *r);
/* |v - want| <= tol seconds */
int  hci_near(LONGLONG v, LONGLONG want, LONGLONG tol_sec);
/* FILETIME for now + off seconds */
FILETIME hci_ft_off(LONGLONG off_sec);
FILETIME hci_ft_make(LONGLONG ticks);
/* SetUrlCacheEntryInfoA with only the given time field(s): pass HCI_KEEP to leave a field alone */
#define HCI_KEEP 0x7fffffffffffffffLL
BOOL hci_set_times(const char *url, LONGLONG exp_off, LONGLONG lm_off, LONGLONG sync_off);
BOOL hci_set_type(const char *url, DWORD type);
/* local file content equals p[0..n) */
int  hci_file_eq(const char *path, const void *p, size_t n);
/* FILETIME of a fixed UTC date */
LONGLONG hci_ft_utc(int y, int mo, int d, int h, int mi, int s);
/* expected headers on request i (NULL = must be absent) */
const char *hci_rh(srv *s, int i, const char *name);
/* create + commit an entry through the cache API (type, header blob, expire/lm offsets in seconds, 0 = none) */
int  hci_seed(const char *url, const char *body, const char *hdrs, DWORD type, LONGLONG exp_sec, LONGLONG lm_sec);
#ifndef INTERNET_FLAG_FWD_BACK
#define INTERNET_FLAG_FWD_BACK 0x00000020
#endif
#ifndef INTERNET_REQFLAG_NET_TIMEOUT
#define INTERNET_REQFLAG_NET_TIMEOUT 0x00000080
#endif
#ifndef INTERNET_REQFLAG_NO_HEADERS
#define INTERNET_REQFLAG_NO_HEADERS 0x00000008
#endif
#define HCI_HTTP_ENTRY 0x41    /* NORMAL_CACHE_ENTRY | 0x40: what an HTTP download commits (VM) */
#endif
