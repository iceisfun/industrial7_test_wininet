/* session_handles - shared helpers for the area (prefix sh_).
 * InternetOpen/InternetConnect/InternetCloseHandle, handle types, per-handle-type option rules.
 * All wininet entry points go through U()/UIN(); nothing is linked. Evidence: tests/session_handles/EVIDENCE.md. */
#ifndef SH_H
#define SH_H
#include "t.h"
#include <winsock2.h>
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

#define SH_GARBAGE1 ((HINTERNET)(ULONG_PTR)0x00001234)
#define SH_GARBAGE2 ((HINTERNET)(ULONG_PTR)0x7fff0000)
#define SH_START_OR_SKIP(cfgp, sp) do { int rc_ = srv_start((cfgp), (sp)); if (rc_) { t_skip("server unavailable: %s", srv_strerror(rc_)); return; } } while (0)

/* a DIRECT session with no network effect at creation */
static HINTERNET sh_open(const char *agent) {
    return U(InternetOpenA)(agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
}
static HINTERNET sh_open_to(const char *agent) {             /* DIRECT + 5 s timeouts for tests that talk to a server */
    return (HINTERNET)t_inet_open(agent);
}
static HINTERNET sh_connect(HINTERNET s, const char *host, INTERNET_PORT port, DWORD_PTR ctx) {
    return U(InternetConnectA)(s, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, ctx);
}
static HINTERNET sh_request(HINTERNET c, const char *obj, DWORD_PTR ctx) {
    return U(HttpOpenRequestA)(c, "GET", obj, NULL, NULL, NULL, T_INET_FRESH, ctx);
}
static BOOL sh_close(HINTERNET h) { return U(InternetCloseHandle)(h); }

/* query a DWORD option; returns 1 on success, 0 on failure (err set) */
static int sh_qdw(HINTERNET h, DWORD opt, DWORD *val, DWORD *len_out, DWORD *err) {
    DWORD v = 0xcccccccc, len = sizeof v;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryOptionA)(h, opt, &v, &len);
    if (err) *err = ok ? 0 : GetLastError();
    if (val) *val = v;
    if (len_out) *len_out = len;
    return ok != 0;
}
/* query an 8-byte option (pointer/context) */
static int sh_qptr(HINTERNET h, DWORD opt, ULONG_PTR *val, DWORD *len_out, DWORD *err) {
    ULONG_PTR v = (ULONG_PTR)0xccccccccccccccccull; DWORD len = sizeof v;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryOptionA)(h, opt, &v, &len);
    if (err) *err = ok ? 0 : GetLastError();
    if (val) *val = v;
    if (len_out) *len_out = len;
    return ok != 0;
}
/* HANDLE_TYPE or 0 on failure (*err) */
static DWORD sh_htype(HINTERNET h, DWORD *err) {
    DWORD v = 0, e = 0;
    if (!sh_qdw(h, INTERNET_OPTION_HANDLE_TYPE, &v, NULL, &e)) { if (err) *err = e; return 0; }
    if (err) *err = 0;
    return v;
}
static HINTERNET sh_parent(HINTERNET h, DWORD *err) {
    ULONG_PTR v = 0; DWORD e = 0;
    if (!sh_qptr(h, INTERNET_OPTION_PARENT_HANDLE, &v, NULL, &e)) { if (err) *err = e; return (HINTERNET)(ULONG_PTR)0xbad; }
    if (err) *err = 0;
    return (HINTERNET)v;
}
/* query a string option (A) into buf; returns 1 ok */
static int sh_qstr(HINTERNET h, DWORD opt, char *buf, DWORD cap, DWORD *len_out, DWORD *err) {
    DWORD len = cap; if (buf && cap) buf[0] = 0;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryOptionA)(h, opt, buf, &len);
    if (err) *err = ok ? 0 : GetLastError();
    if (len_out) *len_out = len;
    return ok != 0;
}
static int sh_qstrw(HINTERNET h, DWORD opt, WCHAR *buf, DWORD cap_bytes, DWORD *len_out, DWORD *err) {
    DWORD len = cap_bytes; if (buf && cap_bytes) buf[0] = 0;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryOptionW)(h, opt, buf, &len);
    if (err) *err = ok ? 0 : GetLastError();
    if (len_out) *len_out = len;
    return ok != 0;
}
static int sh_set(HINTERNET h, DWORD opt, void *buf, DWORD len, DWORD *err) {
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetSetOptionA)(h, opt, buf, len);
    if (err) *err = ok ? 0 : GetLastError();
    return ok != 0;
}
static int sh_setdw(HINTERNET h, DWORD opt, DWORD v, DWORD *err) { return sh_set(h, opt, &v, sizeof v, err); }

/* A "dead" loopback port: a server that was started and stopped (nothing listens there any more). */
static unsigned short sh_dead_port(void) {
    srv *s = srv_http(NULL, 0);
    if (!s) return 0;
    unsigned short p = srv_port(s);
    srv_stop(s);
    return p;
}

/* FTP server with a small tree, for FCon/FFnd/FFil handles. */
static const srv_ftp_file sh_ftp_files[] = {
    { "/hello.txt", "hello", 5, "20200102030405" },
    { "/data.bin", "0123456789", 10, "20200102030405" },
    { "/pub/", NULL, -1 },
    { "/pub/a.txt", "aaa", 3, "20200102030405" },
};
static srv *sh_ftp_start(void) {
    static srv_ftp_config fc;
    fc.files = sh_ftp_files; fc.nfiles = 4;
    srv_config cfg = { SRV_FTP }; cfg.ftp = &fc;
    srv *s = NULL;
    if (srv_start(&cfg, &s)) return NULL;
    return s;
}

/* Status-callback recorder (thread-safe, bounded). */
typedef struct { HINTERNET h; DWORD_PTR ctx; DWORD status; DWORD infolen; ULONG_PTR info0; DWORD tid; } sh_cb_ev;
typedef struct {
    CRITICAL_SECTION cs; LONG cs_init; int n; sh_cb_ev ev[512];
    HINTERNET close_on_status_h; DWORD close_on_status; int closed_ok; DWORD closed_err; int close_done;
} sh_cb_rec;
extern sh_cb_rec *sh_cb_cur;
void CALLBACK sh_cb(HINTERNET h, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD infolen);
void sh_cb_reset(sh_cb_rec *r);
int  sh_cb_count(sh_cb_rec *r, DWORD status, DWORD_PTR ctx);   /* ctx (DWORD_PTR)-1 = any */
int  sh_cb_first(sh_cb_rec *r, DWORD status, DWORD_PTR ctx);   /* index or -1 */
#endif
