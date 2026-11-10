/* options probe (scratch, not committed): sweeps InternetQueryOption/InternetSetOption over options x handle kinds.
 * VM_TIMEOUT: 600 */
#include "t.h"
#include <winsock2.h>
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

enum { HN, HS, HC, HR, HX, HT, HF, HL, HK };
static const char *hk = "NSCRXTFL";
static HINTERNET H[HK];
static srv *s_http, *s_https, *s_ftp;

static void hexd(const unsigned char *p, DWORD n) { if (n > 48) n = 48; for (DWORD i = 0; i < n; i++) printf("%02x", p[i]); }

static void mk_handles(int want_tls_ftp) {
    memset(H, 0, sizeof H);
    s_http = srv_http(NULL, 0);
    H[HS] = U(InternetOpenA)("probe-agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (s_http) {
        H[HC] = U(InternetConnectA)(H[HS], "127.0.0.1", srv_port(s_http), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        H[HR] = U(HttpOpenRequestA)(H[HC], "GET", "/p", NULL, NULL, NULL, T_INET_FRESH, 0);
        H[HX] = U(HttpOpenRequestA)(H[HC], "GET", "/x", NULL, NULL, NULL, T_INET_FRESH, 0);
        if (H[HX] && U(HttpSendRequestA)(H[HX], NULL, 0, NULL, 0)) { char b[64]; t_inet_read_all(H[HX], b, sizeof b, NULL); }
        else printf("PROBE X send failed %lu\n", GetLastError());
    }
    if (!want_tls_ftp) return;
    s_https = srv_https(NULL, 0, SRV_CERT_LOCALHOST);
    if (s_https) {
        HINTERNET c = U(InternetConnectA)(H[HS], "127.0.0.1", srv_port(s_https), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        H[HT] = U(HttpOpenRequestA)(c, "GET", "/t", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0);
        BOOL ok = FALSE;
        for (int k = 0; k < 3 && !ok; k++) { ok = U(HttpSendRequestA)(H[HT], NULL, 0, NULL, 0); if (!ok) { printf("PROBE T try %d err %lu\n", k, GetLastError()); t_https_secflags(H[HT], 0x100); } }
        if (ok) { char b[64]; t_inet_read_all(H[HT], b, sizeof b, NULL); }
        else printf("PROBE T send failed %lu\n", GetLastError());
    } else printf("PROBE https unavailable\n");
    static const srv_ftp_file files[] = { { "/hello.txt", "hello", 5, "20200102030405" } };
    static srv_ftp_config fc = { files, 1 };
    srv_config cfg = { SRV_FTP }; cfg.ftp = &fc;
    if (!srv_start(&cfg, &s_ftp)) {
        H[HF] = U(InternetConnectA)(H[HS], "127.0.0.1", srv_port(s_ftp), "anonymous", "x@y", INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
        if (!H[HF]) printf("PROBE F connect failed %lu\n", GetLastError());
    }
    char path[MAX_PATH], url[MAX_PATH + 16]; t_tmpfile(path, sizeof path, "f.txt");
    FILE *f = fopen(path, "wb"); if (f) { fputs("filedata", f); fclose(f); }
    snprintf(url, sizeof url, "file://%s", path);
    H[HL] = U(InternetOpenUrlA)(H[HS], url, NULL, 0, 0, 0);
    if (!H[HL]) printf("PROBE L openurl failed %lu\n", GetLastError());
    printf("PROBE handles");
    for (int i = 0; i < HK; i++) printf(" %c=%p", hk[i], H[i]);
    printf("\n");
}

static void q(int opt, int h, int w) {
    static unsigned char buf[8192];
    DWORD len; BOOL r; DWORD e; ULONGLONG t0;
    /* q0: NULL buffer, len 0 */
    len = 0; SetLastError(0xdead); t0 = GetTickCount64();
    r = w ? U(InternetQueryOptionW)(H[h], opt, NULL, &len) : U(InternetQueryOptionA)(H[h], opt, NULL, &len);
    e = GetLastError();
    printf("Q %d %c %c 0 r=%d e=%lu l=%lu\n", opt, hk[h], w ? 'W' : 'A', r, e, len);
    /* q1: big buffer */
    memset(buf, opt == 75 ? 0 : 0xCC, sizeof buf); len = 4096; SetLastError(0xdead);
    r = w ? U(InternetQueryOptionW)(H[h], opt, buf, &len) : U(InternetQueryOptionA)(H[h], opt, buf, &len);
    e = GetLastError();
    printf("Q %d %c %c 1 r=%d e=%lu l=%lu d=", opt, hk[h], w ? 'W' : 'A', r, e, len);
    if (r) hexd(buf, len * (w ? 2 : 1) < 48 ? len * (w ? 2 : 1) + (w ? 2 : 1) : 48);
    unsigned ms = (unsigned)(GetTickCount64() - t0);
    if (ms > 200) printf(" ms=%u", ms);
    printf("\n");
    if (r && len > 0 && len < 4096) {
        DWORD L = len;
        memset(buf, 0xCC, sizeof buf); len = L; SetLastError(0xdead);
        r = w ? U(InternetQueryOptionW)(H[h], opt, buf, &len) : U(InternetQueryOptionA)(H[h], opt, buf, &len);
        printf("Q %d %c %c 2 r=%d e=%lu l=%lu\n", opt, hk[h], w ? 'W' : 'A', r, GetLastError(), len);
        memset(buf, 0xCC, sizeof buf); len = 1; SetLastError(0xdead);
        r = w ? U(InternetQueryOptionW)(H[h], opt, buf, &len) : U(InternetQueryOptionA)(H[h], opt, buf, &len);
        printf("Q %d %c %c 3 r=%d e=%lu l=%lu b0=%02x\n", opt, hk[h], w ? 'W' : 'A', r, GetLastError(), len, buf[0]);
    }
}

static int g_made, g_next = 0;
static const int extra[] = { 201, 202, 255, 256, 1000, 99999, -1 };
static void probe_one(void) {
    if (!g_made) { g_made = 1; mk_handles(1);
        for (int h = 0; h < HK; h++) { DWORD v; SetLastError(0xdead); BOOL r = U(InternetQueryOptionA)(H[h], 2, &v, NULL); printf("QN %c r=%d e=%lu\n", hk[h], r, GetLastError()); } }
    int i = g_next++;
    int opt = i <= 200 ? i : extra[i - 201];
    for (int h = 0; h < HK; h++) {
        if (h != HN && !H[h]) continue;
        q(opt, h, 0); q(opt, h, 1);
        fflush(stdout);
    }
}
static void __attribute__((constructor)) reg_probe(void) {
    static char names[220][16];
    for (int i = 0; i < 208; i++) { snprintf(names[i], 16, "pq_%03d", i); t_register(names[i], probe_one); }
}

static void s1(int opt, int h, int w, const char *v, const void *b, DWORD l) {
    SetLastError(0xdead);
    BOOL r = w ? U(InternetSetOptionW)(H[h], opt, (void *)b, l) : U(InternetSetOptionA)(H[h], opt, (void *)b, l);
    printf("S %d %c %c %s r=%d e=%lu\n", opt, hk[h], w ? 'W' : 'A', v, r, GetLastError());
}

CHILD(setp) {
    int lo = atoi(argv[1]), hi = atoi(argv[2]);
    for (int opt = lo; opt <= hi; opt++) {
        mk_handles(0);
        static const int order[] = { HS, HC, HR, HX, HN };
        for (int oi = 0; oi < 5; oi++) {
            int h = order[oi];
            if (h != HN && !H[h]) continue;
            DWORD z = 0; unsigned char rb[4096]; DWORD rl;
            for (int w = 0; w < 2; w++) {
                s1(opt, h, w, "nul0", NULL, 0);
                s1(opt, h, w, "nul4", NULL, 4);
                s1(opt, h, w, "buf0", &z, 0);
                s1(opt, h, w, "len1", &z, 1);
                s1(opt, h, w, "len3", &z, 3);
                memset(rb, 0, sizeof rb); rl = sizeof rb;
                BOOL qr = w ? U(InternetQueryOptionW)(H[h], opt, rb, &rl) : U(InternetQueryOptionA)(H[h], opt, rb, &rl);
                if (qr) s1(opt, h, w, "rt", rb, rl);
            }
            ULONGLONG zz = 0; DWORD one = 1, big = 0x7fffffff;
            for (int w = 0; w < 2; w++) {
                s1(opt, h, w, "len8z", &zz, 8);
                s1(opt, h, w, "len5", &zz, 5);
                s1(opt, h, w, "d0", &z, 4);
                s1(opt, h, w, "d1", &one, 4);
                s1(opt, h, w, "dbig", &big, 4);
            }
        }
        for (int i = HK - 1; i > 0; i--) if (H[i]) U(InternetCloseHandle)(H[i]);
        srv_stop(s_http); s_http = NULL;
        fflush(stdout);
    }
    return 0;
}

static DWORD run_child_io(const char *a, DWORD to) {
    HANDLE o = GetStdHandle(STD_OUTPUT_HANDLE); SetHandleInformation(o, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    PROCESS_INFORMATION pi; DWORD code = 0xDEAD0000;
    HANDLE h = t_spawn_child("setp", a, 0, NULL, o, o, TRUE, NULL, &pi);
    if (!h) return code;
    if (WaitForSingleObject(h, to) != WAIT_OBJECT_0) { TerminateProcess(h, 1); WaitForSingleObject(h, 5000); code = 0xDEAD0001; }
    else GetExitCodeProcess(h, &code);
    CloseHandle(pi.hThread); CloseHandle(h);
    return code;
}
TEST(zz_probe_set) {
    if (1) return;
    REQUIRE(U(InternetSetOptionA));
    static const int skip[] = { 0 };
    for (int lo = 0; lo <= 200; lo += 1) {
        char a[64]; snprintf(a, sizeof a, "%d %d", lo, lo);
        fflush(stdout);
        DWORD rc = run_child_io(a, 15000);
        printf("SETCHILD %s rc=0x%lx\n", a, rc);
    }
    char a[64]; snprintf(a, sizeof a, "%d %d", 99999, 99999); run_child_io(a, 20000);
}
