/* bio.h - shared helpers of the http_body_io area (prefix bio_). Body handling: InternetReadFile(Ex),
 * InternetQueryDataAvailable, InternetSetFilePointer, framing (Content-Length / chunked / close-delimited),
 * decoding, timeouts, keep-alive. Every peer is an in-process loopback server (common/srv.h).
 * Evidence levels are listed in tests/http_body_io/EVIDENCE.md. */
#ifndef BIO_H
#define BIO_H
#include "t.h"
#include <winsock2.h>
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

#ifndef ERROR_INTERNET_DECODING_FAILED
#define ERROR_INTERNET_DECODING_FAILED 12175
#endif

typedef struct { srv *s; HINTERNET hi, hc; } bio_env;

/* Start a server running steps (connection i runs the same script) and open a DIRECT session + connect handle.
 * Returns 0 after t_skip() when the server or wininet is unavailable. */
int  bio_open(bio_env *e, const srv_step *st, int n);
int  bio_open_cfg(bio_env *e, const srv_config *cfg);
void bio_close(bio_env *e);                       /* close connect + session, then stop the server */
/* HttpOpenRequestA(verb, path, HTTP/1.1, T_INET_FRESH | extra) + HttpSendRequestA(hdrs). ok and err receive the send result. */
HINTERNET bio_req(bio_env *e, const char *verb, const char *path, DWORD extra_flags, const char *hdrs, BOOL *ok, DWORD *err);
HINTERNET bio_get(bio_env *e, const char *path);  /* GET, CHECKs that the send succeeded */
void bio_h(HINTERNET h);                          /* InternetCloseHandle, NULL ok */

typedef struct {
    size_t n;        /* bytes stored (and returned in total) */
    int ok;          /* last InternetReadFile succeeded (loop ended on a 0-byte read) */
    DWORD err;       /* GetLastError of the failing call */
    int calls;       /* InternetReadFile calls that returned data */
    int over;        /* calls that reported more bytes than requested (must stay 0) */
    DWORD maxrd;     /* largest single read */
} bio_rd;
/* Read until a 0-byte read or a failure, piece bytes per call (0 = 65536). cap must exceed the body: bytes beyond
 * cap are counted in n but dropped. */
size_t bio_read(HINTERNET h, void *buf, size_t cap, DWORD piece, bio_rd *r);
/* Same with InternetReadFileExA (INTERNET_BUFFERSA, flags) */
size_t bio_read_ex(HINTERNET h, void *buf, size_t cap, DWORD piece, DWORD flags, bio_rd *r);

DWORD bio_status(HINTERNET h);                    /* HTTP_QUERY_STATUS_CODE | FLAG_NUMBER, 0 on failure */
/* String header query (HttpQueryInfoA). NULL when it fails; *err = GetLastError (may be NULL). */
const char *bio_hdr(HINTERNET h, DWORD q, char *buf, DWORD cap, DWORD *err);
const char *bio_custom(HINTERNET h, const char *name, char *buf, DWORD cap, DWORD *err);
/* QDA; returns the value, (DWORD)-1 on failure with *err */
DWORD bio_qda(HINTERNET h, DWORD *err);
int  bio_set_dword(HINTERNET h, DWORD opt, DWORD v);

unsigned char *bio_pattern(size_t n);             /* malloc'd srv_pattern_byte(0..n-1) */
int  bio_sha256(const void *p, size_t n, unsigned char out[32]); /* advapi32 CryptoAPI scaffolding; 1 ok */
#endif
