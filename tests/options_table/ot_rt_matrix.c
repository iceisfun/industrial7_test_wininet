/* options_table: set -> query round trips for every option 0..200 with DWORD values, frozen from the Win10 VM.
 *
 * Each option runs in its own child process (CHILD ot_rtm) on fresh unsent handles, replaying exactly the sequence
 * of the VM probe (gen/probe.c CHILD rtp) and comparing every step with ot_rtab.c (gen/gen_rtab.py):
 *   for h in N (NULL), S (session), C (HTTP connect to 127.0.0.1:1, never connected), R (unsent GET on C):
 *     query A (4096-byte buffer)
 *     for v in 0, 1, 2, 3, 4, 0x10, 0x7fffffff, 0x80000000: InternetSetOptionA(h, opt, &v, 4), then query A again
 * The sequence is cumulative per handle, so a token shows what the last accepted value turned into (clamped,
 * normalised to 0/1, masked, ignored...). Query tokens compare r, GetLastError (on FALSE), *len and the first
 * min(len, 8) value bytes; "*" tokens (differed between probe passes, or pointer/handle/time values) are skipped.
 * Not run here: 37 REFRESH, 39 SETTINGS_CHANGED, 42 END_BROWSER_SESSION, 75 PER_CONNECTION_OPTION, 95, 154
 * (process-external effects; see ot_set_matrix.c and EVIDENCE.md).
 * VM_TIMEOUT: 400 */
#include "ot.h"
#include "ot_tab.h"

static const DWORD RT_VALS[] = { 0, 1, 2, 3, 4, 0x10, 0x7fffffff, 0x80000000u };

static int next_tok(const char **p, char *out, size_t cap) {
    const char *s = *p; size_t n = 0;
    if (!*s) return 0;
    while (*s && *s != ',') { if (n + 1 < cap) out[n++] = *s; s++; }
    out[n] = 0; if (*s == ',') s++; *p = s;
    return 1;
}

static void qtok(HINTERNET h, DWORD opt, char *out, size_t cap) {
    static unsigned char b[4096]; DWORD l = sizeof b; memset(b, 0xCC, sizeof b); SetLastError(0xdead);
    BOOL r = U(InternetQueryOptionA)(h, opt, b, &l); DWORD e = GetLastError();
    if (r) snprintf(out, cap, "%lu=%s", l, ot_hex(b, l < 8 ? l : 8));
    else snprintf(out, cap, "!%lu/%lu", e, l);
}

static int tok_eq(const char *got, const char *want) {
    if (!strcmp(want, "*")) return 1;
    if (!strcmp(got, want)) return 1;
    /* "4=x": success with this length, value masked */
    const char *x = strchr(want, '=');
    if (x && !strcmp(x + 1, "x")) { const char *g = strchr(got, '='); return g && (g - got) == (x - want) && !strncmp(got, want, x - want); }
    return 0;
}

CHILD(ot_rtm) {
    if (argc < 2) return 0xC0DE0002;
    int opt = atoi(argv[1]); const char *exp = NULL;
    for (int i = 0; i < ot_rtab_n; i++) if (ot_rtab[i].opt == opt) exp = ot_rtab[i].exp;
    if (!exp) return 0xC0DE0003;
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 1, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET r = U(HttpOpenRequestA)(c, "GET", "/rt", NULL, NULL, NULL, T_INET_FRESH, 0);
    if (!s || !c || !r) { printf("  RTM opt=%d handles failed\n", opt); return 0xC0DE0004; }
    HINTERNET hs[4] = { NULL, s, c, r }; const char *kn = "NSCR";
    const char *p = exp; char want[64], got[64]; int bad = 0, n = 0;
    for (int k = 0; k < 4; k++) {
        if (!next_tok(&p, want, sizeof want)) return 0xC0DE0005;
        qtok(hs[k], opt, got, sizeof got); n++;
        if (!tok_eq(got, want)) { printf("  RTM opt=%d h=%c initial query got %s want %s\n", opt, kn[k], got, want); bad++; }
        for (int i = 0; i < 8; i++) {
            DWORD v = RT_VALS[i];
            if (!next_tok(&p, want, sizeof want)) return 0xC0DE0005;
            SetLastError(0xdead);
            BOOL sr = U(InternetSetOptionA)(hs[k], opt, &v, 4); DWORD se = GetLastError();
            if (sr) strcpy(got, "ok"); else snprintf(got, sizeof got, "%lu", se);
            n++;
            if (!tok_eq(got, want)) { printf("  RTM opt=%d h=%c set 0x%lx got %s want %s\n", opt, kn[k], v, got, want); bad++; }
            if (!next_tok(&p, want, sizeof want)) return 0xC0DE0005;
            qtok(hs[k], opt, got, sizeof got); n++;
            if (!tok_eq(got, want)) { printf("  RTM opt=%d h=%c query after set 0x%lx got %s want %s\n", opt, kn[k], v, got, want); bad++; }
        }
    }
    printf("  RTM opt=%d compared=%d mismatches=%d\n", opt, n, bad);
    fflush(stdout);
    return bad;
}

static void run_range(int lo, int hi) {
    REQUIRE(U(InternetSetOptionA));
    REQUIRE(U(InternetQueryOptionA));
    if (!ot_rtab_n) { t_skip("no frozen round-trip table"); return; }
    int ran = 0;
    for (int i = 0; i < ot_rtab_n; i++) {
        int opt = ot_rtab[i].opt;
        if (opt < lo || opt > hi) continue;
        char a[16]; snprintf(a, sizeof a, "%d", opt);
        DWORD rc = ot_run_child_io("ot_rtm", a, 20000);
        CHECKF(rc == 0, "option %d: child exit 0x%lx (mismatch count, or 0xC0DE/0xDEAD failure)", opt, rc);
        ran++;
    }
    CHECKF(ran > 0, "no rows in [%d,%d]", lo, hi);
}

#define RTM(lo, hi) TEST(ot_rtm_##lo##_##hi) { run_range(lo, hi); }
RTM(0, 19)
RTM(20, 39)
RTM(40, 59)
RTM(60, 79)
RTM(80, 99)
RTM(100, 119)
RTM(120, 139)
RTM(140, 159)
RTM(160, 179)
RTM(180, 200)
