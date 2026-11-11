/* options_table: MAX_CONNS_PER_SERVER (73) / MAX_CONNS_PER_1_0_SERVER (74) on connect handles, each scenario in a
 * fresh child process.
 *
 * Why children: the per-server limit lives in a CServerInfo record that is shared per lower-cased host name
 * (GetServerInfo@0x64198: _strlwr + FindServerInfo, no port in the key), and a connect handle only points at one
 * (field +0x3d0) once a record exists for its host. Whether a record exists depends on every earlier request to
 * that host name in the process, which is why the hand-written parent tests gave different answers in different
 * runs. A fresh process has no records, so each scenario below is deterministic.
 * Decomp: InternetQueryOptionA case 0x49 (NULL -> GlobalMaxConnectionsPerServer; HCon -> record +0x180, or 12016
 * without a record; other handles 12016), case 0x4a (NULL -> GlobalMaxConnectionsPer1_0Server; any real handle 12016);
 * InternetSetOptionA case 0x49/0x4a (length != 4 -> 12010, 0 -> 160, EnsureRangeLimits(2,128); NULL -> set the
 * global AND CServerInfo::SetNewLimit on every record of GlobalServerInfoList; HCon -> SetNewLimit on its record or
 * 12016; 0x4a on a real handle -> 12016). */
#include "ot.h"

static int g_bad;
#define CK(c, ...) do { if (!(c)) { printf("  MC MISMATCH line %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); g_bad++; } } while (0)

typedef struct { BOOL r; DWORD e, v, l; } qres;
static qres q(HINTERNET h, DWORD opt) {
    qres x; x.v = 0xdeadbeef; x.l = 4; SetLastError(0xdead);
    x.r = U(InternetQueryOptionA)(h, opt, &x.v, &x.l); x.e = x.r ? 0 : GetLastError();
    return x;
}
static DWORD s_err(HINTERNET h, DWORD opt, DWORD v) {
    SetLastError(0xdead);
    return U(InternetSetOptionA)(h, opt, &v, 4) ? 0 : GetLastError();
}
static HINTERNET conn(HINTERNET s, const char *host, unsigned short port) {
    return U(InternetConnectA)(s, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
}
/* one completed GET through c (creates the CServerInfo record for c's host name) */
static int do_get(HINTERNET c) {
    HINTERNET r = U(HttpOpenRequestA)(c, "GET", "/mc", NULL, NULL, NULL, T_INET_FRESH, 0);
    if (!r) return 0;
    BOOL ok = U(HttpSendRequestA)(r, NULL, 0, NULL, 0);
    char b[64]; if (ok) t_inet_read_all(r, b, sizeof b, NULL);
    U(InternetCloseHandle)(r);
    return ok;
}

/* fresh process, no request yet: an unused connect has no record */
static int sc_fresh(void) {
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET c = s ? conn(s, "127.0.0.1", 1) : NULL;
    if (!c) return 0xC0DE0004;
    qres a = q(c, INTERNET_OPTION_MAX_CONNS_PER_SERVER);
    /* Win10 22H2 observed: a record-less connect answers with the global value (2), not 12016 */
    qres gl = q(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER);
    CK(a.r && a.l == 4 && a.v == gl.v, "PER_SERVER on a record-less connect r=%d e=%lu v=%lu global %lu", a.r, a.e, a.v, gl.v);
    a = q(c, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER);
    CK(!a.r && a.e == ERROR_INTERNET_INVALID_OPERATION, "PER_1_0 on a connect r=%d e=%lu", a.r, a.e);
    DWORD e;
    e = s_err(c, INTERNET_OPTION_MAX_CONNS_PER_SERVER, 4);    CK(e == 0, "set PER_SERVER 4: %lu (Win10 accepts on a record-less connect)", e);
    e = s_err(c, INTERNET_OPTION_MAX_CONNS_PER_SERVER, 0);    CK(e == ERROR_BAD_ARGUMENTS, "set PER_SERVER 0: %lu (0 is rejected first)", e);
    e = s_err(c, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER, 4); CK(e == ERROR_INTERNET_INVALID_OPERATION, "set PER_1_0 4: %lu", e);
    e = s_err(c, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER, 0); CK(e == ERROR_BAD_ARGUMENTS, "set PER_1_0 0: %lu", e);
    /* a short length is checked before the value and the handle */
    WORD w = 4; SetLastError(0xdead);
    CK(!U(InternetSetOptionA)(c, INTERNET_OPTION_MAX_CONNS_PER_SERVER, &w, 2) && GetLastError() == ERROR_INTERNET_BAD_OPTION_LENGTH, "set len 2: %lu", GetLastError());
    U(InternetCloseHandle)(c); U(InternetCloseHandle)(s);
    return 0;
}

/* after one request to 127.0.0.1: every connect to that host name shares one record */
static int sc_after(void) {
    srv *sv = srv_http(NULL, 0); if (!sv) return 0xC0DE0007;
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET c0 = s ? conn(s, "127.0.0.1", 1) : NULL;                 /* created before any record */
    HINTERNET c1 = s ? conn(s, "127.0.0.1", srv_port(sv)) : NULL;
    if (!c0 || !c1) return 0xC0DE0004;
    CK(do_get(c1), "GET failed %lu", GetLastError());
    qres g = q(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER);
    CK(g.r && g.l == 4, "global query r=%d", g.r);
    qres a = q(c1, INTERNET_OPTION_MAX_CONNS_PER_SERVER);
    CK(a.r && a.l == 4 && a.v == g.v, "connect that sent: r=%d e=%lu v=%lu global %lu", a.r, a.e, a.v, g.v);
    HINTERNET c2 = conn(s, "127.0.0.1", 2);                            /* other port, same host name */
    a = q(c2, INTERNET_OPTION_MAX_CONNS_PER_SERVER);
    CK(a.r && a.v == g.v, "new connect, same host, other port: r=%d e=%lu v=%lu", a.r, a.e, a.v);
    a = q(c0, INTERNET_OPTION_MAX_CONNS_PER_SERVER);
    printf("  MC connect created before the record: r=%d e=%lu v=%lu\n", a.r, a.e, a.r ? a.v : 0);
    HINTERNET cl = conn(s, "localhost", srv_port(sv));                  /* another host name: no record */
    a = q(cl, INTERNET_OPTION_MAX_CONNS_PER_SERVER);
    CK(a.r && a.v == g.v, "localhost connect (Win10: answers the global value): r=%d e=%lu v=%lu", a.r, a.e, a.v);
    /* PER_1_0 is never answered by a real handle, record or not */
    a = q(c1, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER);
    CK(!a.r && a.e == ERROR_INTERNET_INVALID_OPERATION, "PER_1_0 on the connect: r=%d e=%lu", a.r, a.e);
    DWORD e = s_err(c1, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER, 4);
    CK(e == ERROR_INTERNET_INVALID_OPERATION, "set PER_1_0 on the connect: %lu", e);
    U(InternetCloseHandle)(cl); U(InternetCloseHandle)(c2); U(InternetCloseHandle)(c1); U(InternetCloseHandle)(c0); U(InternetCloseHandle)(s);
    srv_stop(sv);
    return 0;
}

/* a set on one connect changes the shared record, clamped 2..128, and leaves the global alone */
static int sc_set(void) {
    srv *sv = srv_http(NULL, 0); if (!sv) return 0xC0DE0007;
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET c1 = s ? conn(s, "127.0.0.1", srv_port(sv)) : NULL;
    if (!c1) return 0xC0DE0004;
    CK(do_get(c1), "GET failed %lu", GetLastError());
    HINTERNET c2 = conn(s, "127.0.0.1", 2);
    qres g = q(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER);
    DWORD e = s_err(c2, INTERNET_OPTION_MAX_CONNS_PER_SERVER, 5);
    CK(e == 0, "set 5 on c2: %lu", e);
    qres a = q(c1, INTERNET_OPTION_MAX_CONNS_PER_SERVER); CK(a.r && a.v == 5, "c1 after set on c2: r=%d v=%lu", a.r, a.v);
    a = q(c2, INTERNET_OPTION_MAX_CONNS_PER_SERVER);      CK(a.r && a.v == 5, "c2: r=%d v=%lu", a.r, a.v);
    a = q(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER);    CK(a.r && a.v == g.v, "global after a connect set: %lu want %lu", a.v, g.v);
    static const struct { DWORD in, out; } m[] = { { 1, 2 }, { 2, 2 }, { 77, 77 }, { 128, 128 }, { 129, 128 }, { 0x7fffffff, 128 }, { 0x80000000u, 128 } /* unsigned compare: rtab row 73 N */, { 3, 3 } };
    for (int i = 0; i < (int)(sizeof m / sizeof m[0]); i++) {
        e = s_err(c1, INTERNET_OPTION_MAX_CONNS_PER_SERVER, m[i].in); CK(e == 0, "set %lu: %lu", m[i].in, e);
        a = q(c2, INTERNET_OPTION_MAX_CONNS_PER_SERVER); CK(a.r && a.v == m[i].out, "set 0x%lx -> %lu want %lu", m[i].in, a.v, m[i].out);
    }
    e = s_err(c1, INTERNET_OPTION_MAX_CONNS_PER_SERVER, 0); CK(e == ERROR_BAD_ARGUMENTS, "set 0: %lu", e);
    a = q(c1, INTERNET_OPTION_MAX_CONNS_PER_SERVER); CK(a.r && a.v == 3, "after the rejected 0: %lu", a.v);
    U(InternetCloseHandle)(c2); U(InternetCloseHandle)(c1); U(InternetCloseHandle)(s);
    srv_stop(sv);
    return 0;
}

/* a NULL-handle set writes the global and pushes the value into every existing record (both options) */
static int sc_global(void) {
    srv *sv = srv_http(NULL, 0); if (!sv) return 0xC0DE0007;
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET c1 = s ? conn(s, "127.0.0.1", srv_port(sv)) : NULL;
    if (!c1) return 0xC0DE0004;
    CK(do_get(c1), "GET failed %lu", GetLastError());
    qres g10 = q(NULL, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER);
    DWORD e = s_err(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER, 9); CK(e == 0, "global set 9: %lu", e);
    qres a = q(c1, INTERNET_OPTION_MAX_CONNS_PER_SERVER); CK(a.r && a.v == 9, "record after global 9: r=%d v=%lu", a.r, a.v);
    a = q(NULL, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER); CK(a.r && a.v == g10.v, "PER_1_0 global untouched: %lu want %lu", a.v, g10.v);
    e = s_err(NULL, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER, 7); CK(e == 0, "global PER_1_0 set 7: %lu", e);
    a = q(NULL, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER); CK(a.r && a.v == 7, "PER_1_0 global: %lu", a.v);
    a = q(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER); CK(a.r && a.v == 9, "PER_SERVER global after the PER_1_0 set: %lu", a.v);
    /* case 0x4a also calls SetNewLimit(7) on every record */
    a = q(c1, INTERNET_OPTION_MAX_CONNS_PER_SERVER); CK(a.r && a.v == 7, "record after global PER_1_0 7: r=%d v=%lu", a.r, a.v);
    /* a connect created afterwards for the same host shares that record */
    HINTERNET c2 = conn(s, "127.0.0.1", 3);
    a = q(c2, INTERNET_OPTION_MAX_CONNS_PER_SERVER); CK(a.r && a.v == 7, "new connect: r=%d v=%lu", a.r, a.v);
    U(InternetCloseHandle)(c2); U(InternetCloseHandle)(c1); U(InternetCloseHandle)(s);
    srv_stop(sv);
    return 0;
}

CHILD(ot_mc) {
    if (argc < 2 || !U(InternetOpenA)) return 0xC0DE0002;
    int rc;
    if (!strcmp(argv[1], "fresh")) rc = sc_fresh();
    else if (!strcmp(argv[1], "after")) rc = sc_after();
    else if (!strcmp(argv[1], "set")) rc = sc_set();
    else if (!strcmp(argv[1], "global")) rc = sc_global();
    else return 0xC0DE0003;
    printf("  MC %s mismatches=%d rc=0x%x\n", argv[1], g_bad, rc);
    fflush(stdout);
    return rc ? rc : g_bad;
}

static void run(const char *sc) {
    REQUIRE(U(InternetSetOptionA));
    REQUIRE(U(InternetQueryOptionA));
    DWORD rc = ot_run_child_io("ot_mc", sc, 30000);
    CHECKF(rc == 0, "scenario %s: child exit 0x%lx (mismatch count, or 0xC0DE/0xDEAD failure)", sc, rc);
}

TEST(ot_mc_fresh_connect_has_no_record) { run("fresh"); }
TEST(ot_mc_record_shared_per_host_name) { run("after"); }
TEST(ot_mc_connect_set_clamped_shared) { run("set"); }
TEST(ot_mc_global_set_updates_records) { run("global"); }
