/* fc_util.c - helpers for the ftp_client area (see ftp.h). */
#include "ftp.h"
#include <stdlib.h>

/* VM_TIMEOUT: 300 */

const srv_ftp_file fc_std_files[] = {
    { "/hello.txt", "hello", 5, "20200102030405" },
    { "/pub/", NULL, -1 },
    { "/pub/readme.txt", "read me\n", 8, "20190615120000" },
    { "/pub/data.bin", NULL, 100000 },
    { "/crlf.txt", "a\r\nb\r\n", 6 },
    { "/lf.txt", "a\nb\nc", 5 },
    { "/empty.txt", "", 0 },
    { "/dir two/", NULL, -1 },
    { "/dir two/in space.txt", "spaced", 6 },
};
const int fc_std_nfiles = NF(fc_std_files);

int fc_start(fcx *x, const srv_ftp_config *cfg) {
    memset(x, 0, sizeof *x);
    if (cfg) x->cfg = *cfg;
    srv_config sc; memset(&sc, 0, sizeof sc);
    sc.kind = SRV_FTP; sc.ftp = &x->cfg; sc.lifetime_ms = 60000;
    int rc = srv_start(&sc, &x->s);
    if (rc) { x->s = NULL; t_skip("ftp server unavailable: %s", srv_strerror(rc)); return 0; }
    return 1;
}
int fc_start_raw(fcx *x, const srv_step *steps, int nsteps) {
    memset(x, 0, sizeof *x);
    x->script.steps = steps; x->script.nsteps = nsteps;
    srv_config sc; memset(&sc, 0, sizeof sc);
    sc.kind = SRV_HTTP; sc.scripts = &x->script; sc.nscripts = 1; sc.lifetime_ms = 30000;
    int rc = srv_start(&sc, &x->s);
    if (rc) { x->s = NULL; t_skip("server unavailable: %s", srv_strerror(rc)); return 0; }
    return 1;
}
HINTERNET fc_connect(fcx *x, const char *user, const char *pass, DWORD flags) {
    if (!x->hi) x->hi = t_inet_open("ftpc");
    if (!x->hi) return NULL;
    x->hc = U(InternetConnectA)(x->hi, "127.0.0.1", srv_port(x->s), user, pass, INTERNET_SERVICE_FTP, flags, 0);
    return x->hc;
}
int fc_open(fcx *x, const srv_ftp_config *cfg) {
    if (!U(InternetConnectA)) { t_skip("missing export InternetConnectA"); return 0; }
    if (!fc_start(x, cfg)) return 0;
    if (!fc_connect(x, NULL, NULL, INTERNET_FLAG_PASSIVE)) {
        DWORD e = GetLastError();
        CHECKF(0, "InternetConnect(FTP) failed: %lu %s", e, t_inet_errname(e));
        fc_end(x);
        return 0;
    }
    return 1;
}
void fc_end(fcx *x) {
    if (x->hc) { U(InternetCloseHandle)(x->hc); x->hc = NULL; }
    if (x->hi) { U(InternetCloseHandle)(x->hi); x->hi = NULL; }
    if (x->s) { srv_stop(x->s); x->s = NULL; }
}

int fc_ncmd(fcx *x) { return srv_ftp_cmd_count(x->s); }
const char *fc_cmd(fcx *x, int i) { const char *c = srv_ftp_cmd(x->s, i); return c ? c : "(none)"; }
int fc_find(fcx *x, const char *prefix, int from) {
    int n = fc_ncmd(x);
    for (int i = from < 0 ? 0 : from; i < n; i++) { const char *c = srv_ftp_cmd(x->s, i); if (c && !strncmp(c, prefix, strlen(prefix))) return i; }
    return -1;
}
int fc_count(fcx *x, const char *prefix) {
    int n = fc_ncmd(x), k = 0;
    for (int i = 0; i < n; i++) { const char *c = srv_ftp_cmd(x->s, i); if (c && !strncmp(c, prefix, strlen(prefix))) k++; }
    return k;
}
const char *fc_seq(fcx *x, int from) {
    static char bufs[4][2048]; static int r;
    char *b = bufs[r++ & 3]; b[0] = 0; size_t o = 0;
    int n = fc_ncmd(x);
    for (int i = from; i < n; i++) {
        const char *c = srv_ftp_cmd(x->s, i); if (!c) break;
        int k = snprintf(b + o, 2048 - o, "%s%s", i > from ? "|" : "", c);
        if (k < 0 || (size_t)k >= 2048 - o) break;
        o += k;
    }
    return b;
}
int fc_wait_ncmd(fcx *x, int n, DWORD ms) {
    for (DWORD t = 0; t <= ms; t += 20) { if (fc_ncmd(x) >= n) return 1; Sleep(20); }
    return fc_ncmd(x) >= n;
}
int fc_wait_cmd(fcx *x, const char *prefix, DWORD ms) {
    for (DWORD t = 0; t <= ms; t += 20) { if (fc_find(x, prefix, 0) >= 0) return 1; Sleep(20); }
    return fc_find(x, prefix, 0) >= 0;
}
void fc_dump(fcx *x) { int n = fc_ncmd(x); for (int i = 0; i < n; i++) t_note("ftp cmd[%d] %s", i, fc_cmd(x, i)); }

const char *fc_resp(DWORD *err) {
    static char bufs[4][4096]; static int r;
    char *b = bufs[r++ & 3]; b[0] = 0;
    DWORD e = 0xdeadbeef, len = 4096;
    if (!U(InternetGetLastResponseInfoA) || !U(InternetGetLastResponseInfoA)(&e, b, &len)) b[0] = 0;
    if (err) *err = e;
    return b;
}

const char *fc_local(const char *leaf) {
    static char bufs[8][MAX_PATH]; static int r; static LONG seq;
    char *b = bufs[r++ & 7];
    char l[128]; snprintf(l, sizeof l, "ftpc%ld_%s", InterlockedIncrement(&seq), leaf);
    t_tmpfile(b, MAX_PATH, l);
    return b;
}
int fc_put_local(const char *path, const void *p, size_t n) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD w = 0; BOOL ok = n ? WriteFile(h, p, (DWORD)n, &w, NULL) : TRUE;
    CloseHandle(h);
    return ok && w == n;
}
char *fc_get_local(const char *path, size_t *n) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { if (n) *n = 0; return NULL; }
    DWORD sz = GetFileSize(h, NULL), rd = 0;
    char *p = malloc(sz + 1);
    if (!ReadFile(h, p, sz, &rd, NULL)) rd = 0;
    p[rd] = 0; CloseHandle(h);
    if (n) *n = rd;
    return p;
}
int fc_local_exists(const char *path) { return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES; }
void fc_del_local(const char *path) { SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL); DeleteFileA(path); }

int fc_list(fcx *x, const char *pattern, WIN32_FIND_DATAA *out, int cap, DWORD *err) {
    WIN32_FIND_DATAA fd; memset(&fd, 0x5a, sizeof fd);
    if (err) *err = 0;
    HINTERNET hf = U(FtpFindFirstFileA)(x->hc, pattern, &fd, FC_NC, 0);
    if (!hf) { if (err) *err = GetLastError(); return -1; }
    int n = 0;
    if (n < cap) out[n] = fd;
    n++;
    for (int g = 0; g < 5000; g++) {
        memset(&fd, 0x5a, sizeof fd);
        if (!U(InternetFindNextFileA)(hf, &fd)) { if (err) *err = GetLastError(); break; }
        if (n < cap) out[n] = fd;
        n++;
    }
    U(InternetCloseHandle)(hf);
    return n;
}
int fc_list_raw(const char *listing, const char *pattern, WIN32_FIND_DATAA *out, int cap, int *count, DWORD *err) {
    if (!U(FtpFindFirstFileA)) { t_skip("missing export FtpFindFirstFileA"); return 0; }
    fcx x; srv_ftp_config c; memset(&c, 0, sizeof c); c.list_override = listing;
    if (!fc_open(&x, &c)) return 0;
    *count = fc_list(&x, pattern, out, cap, err);
    fc_end(&x);
    return 1;
}
const WIN32_FIND_DATAA *fc_by_name(const WIN32_FIND_DATAA *v, int n, const char *name) {
    for (int i = 0; i < n; i++) if (!strcmp(v[i].cFileName, name)) return &v[i];
    return NULL;
}
void fc_ft_to_st(const FILETIME *ft, SYSTEMTIME *st) { memset(st, 0, sizeof *st); FileTimeToSystemTime(ft, st); }

size_t fc_read(HINTERNET h, char *buf, size_t cap, int *ok) { return t_inet_read_all(h, buf, cap, ok); }
