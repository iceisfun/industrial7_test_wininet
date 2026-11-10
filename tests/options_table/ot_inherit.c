/* options_table: which session-level DWORD options are copied into connect/request handles created afterwards,
 * and which are read live from the parent.
 *
 * For each option (own child process, CHILD ot_inh): fresh session S; query S, C0 and R0 (created before the set);
 * InternetSetOptionA(S, opt, V, 4); create C1/R1; query S, C0, R0, C1, R1. Tokens as in ot_rt_matrix.c
 * ("<len>=<hex>" / "!<err>/<len>"). The expected strings are frozen from the Win10 VM (INH lines printed by the
 * child; see EVIDENCE.md). An empty expectation only prints the observation (t_note mode).
 * VM_TIMEOUT: 400 */
#include "ot.h"

typedef struct { int opt; DWORD v; const char *exp; } inh_row;
/* exp: "S0|C0|R0|set|S|C0|R0|C1|R1" */
static const inh_row INH[] = {
#include "ot_inherit_tab.h"
};
#define NINH (int)(sizeof INH / sizeof INH[0])

static void qtok(HINTERNET h, DWORD opt, char *out, size_t cap) {
    static unsigned char b[4096]; DWORD l = sizeof b; memset(b, 0xCC, sizeof b); SetLastError(0xdead);
    BOOL r = U(InternetQueryOptionA)(h, opt, b, &l); DWORD e = GetLastError();
    if (r) snprintf(out, cap, "%lu=%s", l, ot_hex(b, l < 8 ? l : 8));
    else snprintf(out, cap, "!%lu/%lu", e, l);
}

static HINTERNET mk_conn(HINTERNET s) { return U(InternetConnectA)(s, "127.0.0.1", 1, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0); }
static HINTERNET mk_req(HINTERNET c) { return c ? U(HttpOpenRequestA)(c, "GET", "/inh", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL; }

CHILD(ot_inh) {
    if (argc < 2) return 0xC0DE0002;
    int idx = atoi(argv[1]);
    if (idx < 0 || idx >= NINH) return 0xC0DE0003;
    const inh_row *row = &INH[idx]; DWORD opt = (DWORD)row->opt, v = row->v;
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET c0 = mk_conn(s), r0 = mk_req(c0);
    if (!s || !c0 || !r0) return 0xC0DE0004;
    char line[1024] = "", t[64];
    qtok(s, opt, t, sizeof t); strcat(line, t); strcat(line, "|");
    qtok(c0, opt, t, sizeof t); strcat(line, t); strcat(line, "|");
    qtok(r0, opt, t, sizeof t); strcat(line, t); strcat(line, "|");
    SetLastError(0xdead);
    BOOL sr = U(InternetSetOptionA)(s, opt, &v, 4);
    if (sr) strcat(line, "ok"); else { snprintf(t, sizeof t, "%lu", GetLastError()); strcat(line, t); }
    HINTERNET c1 = mk_conn(s), r1 = mk_req(c1);
    if (!c1 || !r1) return 0xC0DE0004;
    HINTERNET after[] = { s, c0, r0, c1, r1 };
    for (int i = 0; i < 5; i++) { qtok(after[i], opt, t, sizeof t); strcat(line, "|"); strcat(line, t); }
    printf("  INH { %d, 0x%lx, \"%s\" },\n", row->opt, v, line);
    int bad = row->exp[0] && strcmp(line, row->exp);
    if (bad) printf("  INH opt=%d MISMATCH want \"%s\"\n", row->opt, row->exp);
    fflush(stdout);
    U(InternetCloseHandle)(r1); U(InternetCloseHandle)(c1); U(InternetCloseHandle)(r0); U(InternetCloseHandle)(c0); U(InternetCloseHandle)(s);
    return bad;
}

static void run_range(int lo, int hi) {
    REQUIRE(U(InternetSetOptionA));
    int ran = 0, noted = 0;
    for (int i = 0; i < NINH; i++) {
        if (INH[i].opt < lo || INH[i].opt > hi) continue;
        char a[16]; snprintf(a, sizeof a, "%d", i);
        DWORD rc = ot_run_child_io("ot_inh", a, 15000);
        CHECKF(rc == 0, "option %d: child exit 0x%lx", INH[i].opt, rc);
        ran++; if (!INH[i].exp[0]) noted++;
    }
    CHECKF(ran > 0, "no rows in [%d,%d]", lo, hi);
    if (noted) t_note("%d option(s) in [%d,%d] have no frozen expectation (observation only)", noted, lo, hi);
}

TEST(ot_inh_0_99) { run_range(0, 99); }
TEST(ot_inh_100_149) { run_range(100, 149); }
TEST(ot_inh_150_200) { run_range(150, 200); }
