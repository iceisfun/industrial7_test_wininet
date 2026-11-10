/* options_table - shared fixture and helpers for the InternetQueryOption / InternetSetOption matrix.
 * Area prefix: ot_. See EVIDENCE.md for where every expectation comes from. */
#ifndef OT_H
#define OT_H
#include "t.h"
#include <winsock2.h>
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

/* Handle kinds used by the matrix (the letters are what the frozen tables use). */
enum { OT_N, OT_S, OT_C, OT_R, OT_X, OT_T, OT_F, OT_L, OT_NK };
#define OT_KINDS "NSCRXTFL"
/* N  NULL handle (global / per-process options)
 * S  InternetOpenA session, DIRECT, agent OT_AGENT                      (tag Inet)
 * C  InternetConnectA HTTP to the loopback server                       (tag HCon)
 * R  HttpOpenRequestA GET /p, never sent                                (tag HReq)
 * X  HttpOpenRequestA GET /x, sent and the 200 "hello" body read        (tag HReq)
 * T  HTTPS GET /t, sent with SECURITY_FLAG_IGNORE_UNKNOWN_CA, body read (tag HReq, TLS)
 * F  InternetConnectA FTP to the loopback FTP server (passive)          (tag FCon)
 * L  InternetOpenUrlA on a file:// URL of a scratch file                (tag HRlf) */
#define OT_AGENT "probe-agent"   /* same agent as the probe that froze the tables */

typedef struct {
    HINTERNET h[OT_NK];
    srv *http, *https, *ftp;
    char file_path[MAX_PATH];
    char url_x[128], url_t[128], url_r[128];
    int has_tls;
} ot_fx;

/* Build the fixture (mask = bit per kind; N and S are always there). Returns NULL if InternetOpen failed.
 * The X request is sent and read; T is sent with IGNORE_UNKNOWN_CA (after the documented first failure). */
ot_fx *ot_fx_open(unsigned mask);
void   ot_fx_close(ot_fx *fx);
/* Process-wide fixture with every kind, built on first use, closed at exit. */
ot_fx *ot_fx_all(void);
#define OT_MASK_ALL 0xFFu
#define OT_BIT(k) (1u << (k))

/* Call wrappers: query/set with A (w=0) or W (w=1). */
BOOL ot_q(int w, HINTERNET h, DWORD opt, void *buf, DWORD *len);
BOOL ot_s(int w, HINTERNET h, DWORD opt, void *buf, DWORD len);

/* Query a DWORD option with A; returns TRUE and *v on success (len must come back 4). */
BOOL ot_qdw(HINTERNET h, DWORD opt, DWORD *v);
/* Set a DWORD option with A. */
BOOL ot_sdw(HINTERNET h, DWORD opt, DWORD v);

/* Result triple for compact comparisons. */
typedef struct { int r; DWORD e; DWORD l; } ot_res;
/* Expect FALSE with error e (GetLastError) and, when l != (DWORD)-1, *len == l. */
#define OT_ANY ((DWORD)-1)

/* Fresh session/connect/request trio (not sent) for tests that mutate options. */
typedef struct { HINTERNET s, c, r; srv *srv; } ot_trio;
int  ot_trio_open(ot_trio *t, int with_server); /* with_server=0 uses 127.0.0.1:1 for C/R (never connected) */
void ot_trio_close(ot_trio *t);

DWORD ot_run_child_io(const char *name, const char *args, DWORD timeout_ms);
/* Hex of up to n bytes into a static buffer (for notes). */
const char *ot_hex(const void *p, DWORD n);
#endif
