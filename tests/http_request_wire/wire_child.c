/* wire_child.c - wire facts that depend on per-process WinINet state, measured in a fresh child process.
 *
 * Win10 VM: the same exe gives different bytes for non-ASCII object names depending on what ran before in the
 * process. In a process that only did plain requests (boots C1 and C2, filtered runs) the bytes went out raw. After
 * ~150 other tests (boots 1 and C3, full runs) they were percent-encoded as UTF-8, with an invalid byte becoming
 * %EF%BF%BD. The per-server connection limit was also exceeded in the full run (C3) but held in a filtered run (C2).
 * The hard checks below therefore run each case in a fresh child (`exe --child <name> ...`) that reports through a
 * temp file. hrw_zz_encoding_flip_probe notes which earlier operation flips the encoding (observation only). */
#include "hrw.h"
#include <stdlib.h>

/* ------------------------------------------------------------------ child plumbing */
static void hexenc(const char *s, char *o) { static const char h[] = "0123456789abcdef"; for (; *s; s++) { *o++ = h[(unsigned char)*s >> 4]; *o++ = h[*s & 15]; } *o = 0; }
static void hexdec(const char *s, char *o) { while (s[0] && s[1]) { int a = s[0] <= '9' ? s[0] - '0' : s[0] - 'a' + 10, b = s[1] <= '9' ? s[1] - '0' : s[1] - 'a' + 10; *o++ = (char)(a * 16 + b); s += 2; } *o = 0; }
static void put_file(const char *path, const char *text) { FILE *f = fopen(path, "wb"); if (f) { fputs(text, f); fclose(f); } }
static int get_file(const char *path, char *buf, size_t cap) {
    FILE *f = fopen(path, "rb"); if (!f) { buf[0] = 0; return 0; }
    size_t n = fread(buf, 1, cap - 1, f); buf[n] = 0; fclose(f); DeleteFileA(path); return 1;
}
/* run child `name` with "<args> <outfile>", return its exit code and the out file content */
static DWORD run_child(const char *name, const char *args, char *out, size_t cap) {
    static LONG k; char path[MAX_PATH], tag[32]; snprintf(tag, sizeof tag, "hrwc%ld.txt", InterlockedIncrement(&k));
    t_tmpfile(path, sizeof path, tag);
    char a[2048]; snprintf(a, sizeof a, "%s \"%s\"", args, path);
    DWORD rc = t_run_child(name, a, 30000);
    get_file(path, out, cap);
    return rc;
}

/* One plain GET of `obj` (A, or W when wide) on a fresh server; returns the recorded request-target in buf. */
static int target_of(const char *obj, int wide, char *buf, size_t cap) {
    buf[0] = 0;
    srv *s = hrw_srv(); if (!s) return 0;
    HINTERNET hi = t_inet_open("child/1");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr;
    if (wide) { WCHAR w[256]; MultiByteToWideChar(CP_UTF8, 0, obj, -1, w, 256); hr = U(HttpOpenRequestW)(hc, L"GET", w, NULL, NULL, NULL, HRW_F, 0); }
    else hr = U(HttpOpenRequestA)(hc, "GET", obj, NULL, NULL, NULL, HRW_F, 0);
    int ok = hr && U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    if (ok) { char b[64]; t_inet_read_all(hr, b, sizeof b, NULL); }
    if (ok && srv_wait_requests(s, 1, 3000)) snprintf(buf, cap, "%s", srv_req_target(s, 0));
    else snprintf(buf, cap, "(error %lu)", GetLastError());
    if (hr) U(InternetCloseHandle)(hr);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
    return ok;
}

/* exe --child hrw_obj_target <A|W> <hex obj> <outfile> */
CHILD(hrw_obj_target) {
    if (argc < 4) return 2;
    char obj[512], t[1024]; hexdec(argv[2], obj);
    target_of(obj, argv[1][0] == 'W', t, sizeof t);
    put_file(argv[3], t);
    return 0;
}
static void obj_fresh(const char *obj, int wide, const char *want) {
    char hex[1100], args[1200], got[1024];
    hexenc(obj, hex); snprintf(args, sizeof args, "%s %s", wide ? "W" : "A", hex);
    DWORD rc = run_child("hrw_obj_target", args, got, sizeof got);
    CHECKF(rc == 0, "child exit 0x%lx", rc);
    CHECKF(!strcmp(got, want), "fresh process, %s object: target got \"%s\" want \"%s\"", wide ? "W" : "A", got, want);
}
/* Fresh process (Win10 VM boots C1, C2): bytes >= 0x80 go out raw; the W object name is converted to UTF-8, raw. */
TEST(hrw_child_obj_utf8_bytes_raw) { HRW_REQUIRE_HTTP(); obj_fresh("/caf\xc3\xa9", 0, "/caf\xc3\xa9"); }
TEST(hrw_child_obj_high_ansi_raw) { HRW_REQUIRE_HTTP(); obj_fresh("/x\xe9y", 0, "/x\xe9y"); }
TEST(hrw_child_obj_w_unicode_utf8_raw) { HRW_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW)); obj_fresh("/caf\xc3\xa9/\xe4\xb8\xad", 1, "/caf\xc3\xa9/\xe4\xb8\xad"); }
TEST(hrw_child_obj_ascii_unchanged) { HRW_REQUIRE_HTTP(); obj_fresh("/plain?a=1", 0, "/plain?a=1"); }
TEST(hrw_child_obj_space_escaped) { HRW_REQUIRE_HTTP(); obj_fresh("/a b", 0, "/a%20b"); }

/* ------------------------------------------------------------------ encoding flip probe (notes only) */
static void probe_action(int id) {
    srv *s = hrw_srv(); if (!s) return;
    HINTERNET hi = t_inet_open("probe/1");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    char b[64]; HINTERNET h = NULL;
    switch (id) {
    case 1: { HTTP_VERSION_INFO v10 = { 1, 0 }, v11 = { 1, 1 };
              U(InternetSetOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &v10, sizeof v10);
              U(InternetSetOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &v11, sizeof v11); break; }
    case 2: h = U(InternetOpenUrlA)(hi, srv_url(s, "/ou"), NULL, 0, HRW_F, 0); break;
    case 3: { HINTERNET w = U(InternetOpenW)(L"agent-é", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0); if (w) U(InternetCloseHandle)(w); break; }
    case 4: h = U(HttpOpenRequestW)(hc, L"GET", L"/w", NULL, NULL, NULL, HRW_F, 0); if (h) U(HttpSendRequestA)(h, NULL, 0, NULL, 0); break;
    case 5: h = U(HttpOpenRequestW)(hc, L"GET", L"/w", NULL, L"http://r.example/", NULL, HRW_F, 0); if (h) U(HttpSendRequestA)(h, NULL, 0, NULL, 0); break;
    case 6: { char url[200]; snprintf(url, sizeof url, "http://127.0.0.1/%s/", t_uniq("pc"));
              U(InternetSetCookieA)(url, "pk", "v"); t_cookie_track(url, "pk"); t_net_cleanup(); break; }
    case 7: { static const WCHAR *acc[] = { L"text/html", NULL }; h = U(HttpOpenRequestW)(hc, NULL, L"/a", NULL, NULL, acc, HRW_F, 0); if (h) U(HttpSendRequestA)(h, NULL, 0, NULL, 0); break; }
    case 8: { HINTERNET px = hrw_proxy_session(s, "probe/px");
              HINTERNET pc = U(InternetConnectA)(px, "p.i7test.example", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
              HINTERNET pr = U(HttpOpenRequestA)(pc, "GET", "/p", NULL, NULL, NULL, HRW_F, 0);
              if (pr) { U(HttpSendRequestA)(pr, NULL, 0, NULL, 0); t_inet_read_all(pr, b, sizeof b, NULL); U(InternetCloseHandle)(pr); }
              U(InternetCloseHandle)(pc); U(InternetCloseHandle)(px); break; }
    case 9: { HINTERNET c6 = U(InternetConnectA)(hi, "::1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
              HINTERNET r6 = U(HttpOpenRequestA)(c6, "GET", "/6", NULL, NULL, NULL, HRW_F, 0);
              if (r6) { U(HttpSendRequestA)(r6, NULL, 0, NULL, 0); t_inet_read_all(r6, b, sizeof b, NULL); U(InternetCloseHandle)(r6); }
              U(InternetCloseHandle)(c6); break; }
    case 10: { srv *t = srv_https(NULL, 0, SRV_CERT_LOCALHOST);
               if (t) { HINTERNET c2 = U(InternetConnectA)(hi, "127.0.0.1", srv_port(t), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
                        HINTERNET r2 = U(HttpOpenRequestA)(c2, "GET", "/s", NULL, NULL, NULL, HRW_F | INTERNET_FLAG_SECURE, 0);
                        if (r2) { t_https_secflags(r2, SECURITY_FLAG_IGNORE_UNKNOWN_CA); U(HttpSendRequestA)(r2, NULL, 0, NULL, 0); t_inet_read_all(r2, b, sizeof b, NULL); U(InternetCloseHandle)(r2); }
                        U(InternetCloseHandle)(c2); srv_stop(t); }
               break; }
    case 11: { HINTERNET r = U(HttpOpenRequestA)(hc, "GET", "/a b", NULL, NULL, NULL, HRW_F, 0);
               if (r) { U(HttpSendRequestA)(r, NULL, 0, NULL, 0); t_inet_read_all(r, b, sizeof b, NULL); U(InternetCloseHandle)(r); } break; }
    default: break;
    }
    if (h) { t_inet_read_all(h, b, sizeof b, NULL); U(InternetCloseHandle)(h); }
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
/* exe --child hrw_enc_probe <id> <outfile>: "<before>|<after>" for the object "/caf\xc3\xa9" */
CHILD(hrw_enc_probe) {
    if (argc < 3) return 2;
    char t1[256], t2[256], o[600];
    target_of("/caf\xc3\xa9", 0, t1, sizeof t1);
    probe_action(atoi(argv[1]));
    target_of("/caf\xc3\xa9", 0, t2, sizeof t2);
    snprintf(o, sizeof o, "%s|%s", t1, t2);
    put_file(argv[2], o);
    return 0;
}
TEST(hrw_zz_encoding_flip_probe) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(InternetSetCookieA));
    static const char *names[] = { "none", "global HTTP_VERSION 1.0 then 1.1", "InternetOpenUrlA", "InternetOpenW non-ASCII agent",
        "HttpOpenRequestW", "HttpOpenRequestW + referer", "InternetSetCookieA", "HttpOpenRequestW accept types", "proxy session",
        "IPv6 ::1 request", "HTTPS request (ignored CA)", "object with a space" };
    for (int id = 0; id < (int)(sizeof names / sizeof names[0]); id++) {
        char args[16], out[600]; snprintf(args, sizeof args, "%d", id);
        DWORD rc = run_child("hrw_enc_probe", args, out, sizeof out);
        t_note("encoding probe %2d %-34s rc=0x%lx before|after: %s", id, names[id], rc, out);
        /* the "before" half is a fresh process: raw (see above) */
        CHECKF(!strncmp(out, "/caf\xc3\xa9|", 6), "probe %d: fresh-process target not raw: %s", id, out);
    }
}

/* ------------------------------------------------------------------ connection limit in a fresh process */
typedef struct { HINTERNET hc; volatile LONG done; BOOL ok; } bgq;
static DWORD WINAPI bg_third(void *p) {
    bgq *b = (bgq *)p;
    HINTERNET hr = U(HttpOpenRequestA)(b->hc, "GET", "/third", NULL, NULL, NULL, HRW_F, 0);
    b->ok = hr && U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    if (b->ok) { char buf[256]; t_inet_read_all(hr, buf, sizeof buf, NULL); }
    if (hr) U(InternetCloseHandle)(hr);
    InterlockedExchange(&b->done, 1);
    return 0;
}
/* exe --child hrw_limit <outfile>: "lim during conns_during third_done_during ok third_conn first_conn" */
CHILD(hrw_limit) {
    if (argc < 2) return 2;
    static const srv_step st_[] = { S_HEAD(), S_BODY(), S_REPLY_PATTERN(200, NULL, 200000, 0), S_LOOP() };
    srv *s = hrw_srv_steps_io(st_, 4, 5000); if (!s) return 3;
    DWORD lim = 0; hrw_get_dword_opt(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER, &lim);
    HINTERNET hi = t_inet_open("lim/1");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET h1 = U(HttpOpenRequestA)(hc, "GET", "/hold1", NULL, NULL, NULL, HRW_F, 0);
    HINTERNET h2 = U(HttpOpenRequestA)(hc, "GET", "/hold2", NULL, NULL, NULL, HRW_F, 0);
    U(HttpSendRequestA)(h1, NULL, 0, NULL, 0);
    U(HttpSendRequestA)(h2, NULL, 0, NULL, 0);
    bgq b = { hc, 0, FALSE };
    HANDLE th = CreateThread(NULL, 0, bg_third, &b, 0, NULL);
    Sleep(1000);
    int during = srv_req_count(s), cdur = srv_conn_count(s); LONG ddur = b.done;
    char *buf = malloc(300000); t_inet_read_all(h1, buf, 300000, NULL); free(buf);
    U(InternetCloseHandle)(h1);
    if (th) { WaitForSingleObject(th, 8000); CloseHandle(th); }
    srv_wait_requests(s, 3, 3000);
    char o[200]; snprintf(o, sizeof o, "%lu %d %d %ld %d %d %d", lim, during, cdur, ddur, b.ok, srv_req_conn(s, 2), srv_req_conn(s, 0));
    put_file(argv[1], o);
    U(InternetCloseHandle)(h2); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
    return 0;
}
/* Default limit (2 per HTTP/1.1 server), fresh process: a third concurrent request is not put on the wire while two
 * connections hold unread bodies; it goes out once one is drained, on that connection (Win10 VM, boots C1 and C2). */
TEST(hrw_child_limit_third_request_waits) {
    HRW_REQUIRE_HTTP();
    char out[200]; DWORD rc = run_child("hrw_limit", "", out, sizeof out);
    CHECKF(rc == 0, "child exit 0x%lx", rc);
    unsigned long lim = 0; int during = -1, cdur = -1, ok = 0, c2 = -1, c0 = -1; long ddur = -1;
    int n = sscanf(out, "%lu %d %d %ld %d %d %d", &lim, &during, &cdur, &ddur, &ok, &c2, &c0);
    t_note("limit child: %s", out);
    CHECKF(n == 7, "child output \"%s\"", out);
    if (n != 7) return;
    if (lim != 2) { t_skip("MAX_CONNS_PER_SERVER is %lu, not the default 2", lim); return; }
    EXPECT_EQ(during, 2);
    EXPECT_EQ(cdur, 2);
    EXPECT_EQ(ddur, 0);
    CHECK(ok);
    EXPECT_EQ(c2, c0);
}
