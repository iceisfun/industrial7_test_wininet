/* probe_first_https - flake12030: where does the latency of the FIRST HTTPS request in a fresh process go?
 * The parent spawns fresh child processes (--child fh <mode> <outfile>); each child starts the loopback schannel server,
 * does one HTTPS GET with a timeline (GetTickCount ms since srv_start) and the server's events, then writes the report to
 * <outfile>; the parent prints it. Modes: dflt (server io timeout 5000 as in the tests), long (30000), warmschan (client
 * AcquireCredentialsHandle first), warmhttp (plain HTTP GET first), ignrev (SECURITY_FLAG_IGNORE_REVOCATION too).
 * VM_TIMEOUT: 900 */
#include "t.h"
#define SECURITY_WIN32
#include <winsock2.h>
#include <wininet.h>
#include <sspi.h>
#include <schannel.h>
#include "srv.h"
#include "tnet.h"
#include <tlhelp32.h>

static FILE *g_f; static DWORD g_t0;
static void P(const char *fmt, ...) { va_list a; va_start(a, fmt); vfprintf(g_f, fmt, a); va_end(a); fputc('\n', g_f); fflush(g_f); }
#define TL(what, ...) P("   %6lu ms client: " what, (unsigned long)(GetTickCount() - g_t0), ##__VA_ARGS__)


/* poor-man's stack sampler: when HttpSendRequest has been running for 800 ms / 2500 ms, dump every other thread's
 * return-address-looking stack words as module+offset (no symbols on the guest; resolve offsets in the corpus). */
static volatile LONG g_inreq, g_sampler_stop; static DWORD g_main_tid;
static void dump_threads(const char *tag) {
    HANDLE ss = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); THREADENTRY32 te; te.dwSize = sizeof te;
    if (ss == INVALID_HANDLE_VALUE) return;
    for (BOOL b = Thread32First(ss, &te); b; b = Thread32Next(ss, &te)) {
        if (te.th32OwnerProcessID != GetCurrentProcessId() || te.th32ThreadID == GetCurrentThreadId()) continue;
        HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID); if (!th) continue;
        if (SuspendThread(th) == (DWORD)-1) { CloseHandle(th); continue; }
        CONTEXT cx; memset(&cx, 0, sizeof cx); cx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        char line[2048]; int n = 0; line[0] = 0;
        if (GetThreadContext(th, &cx)) {
            unsigned long long sp = cx.Rsp; ULONG_PTR rip = (ULONG_PTR)cx.Rip; HMODULE m; char nm[MAX_PATH];
            n += snprintf(line + n, sizeof line - n, " rip=");
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)rip, &m) && GetModuleFileNameA(m, nm, sizeof nm)) {
                const char *bn = strrchr(nm, '\\'); n += snprintf(line + n, sizeof line - n, "%s+0x%llx", bn ? bn + 1 : nm, (unsigned long long)(rip - (ULONG_PTR)m)); }
            unsigned long long stk[512]; SIZE_T got = 0;
            if (ReadProcessMemory(GetCurrentProcess(), (void *)sp, stk, sizeof stk, &got)) {
                int shown = 0;
                for (size_t i = 0; i < got / 8 && shown < 40; i++) {
                    ULONG_PTR v = (ULONG_PTR)stk[i];
                    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)v, &m) && GetModuleFileNameA(m, nm, sizeof nm)) {
                        const char *bn = strrchr(nm, '\\'); if (v - (ULONG_PTR)m < 0x1000) continue;
                        n += snprintf(line + n, sizeof line - n, " %s+0x%llx", bn ? bn + 1 : nm, (unsigned long long)(v - (ULONG_PTR)m)); shown++;
                        if (n > 1900) break;
                    }
                }
            }
        }
        ResumeThread(th); CloseHandle(th);
        P("   SAMPLE %s tid=%lu%s%s", tag, (unsigned long)te.th32ThreadID, te.th32ThreadID == g_main_tid ? "(main)" : "", line);
    }
    CloseHandle(ss);
}
static DWORD WINAPI sampler(LPVOID p) {
    DWORD t0 = GetTickCount(); int did1 = 0, did2 = 0;
    while (!g_sampler_stop) {
        Sleep(50);
        if (!g_inreq) { t0 = GetTickCount(); continue; }
        DWORD d = GetTickCount() - t0;
        if (!did1 && d > 800) { did1 = 1; P("   SLOW request %lu ms", (unsigned long)d); dump_threads("800ms"); }
        if (!did2 && d > 2500) { did2 = 1; dump_threads("2500ms"); }
    }
    return 0;
}

CHILD(fh) {
    const char *mode = argc > 1 ? argv[1] : "dflt";
    g_f = fopen(argc > 2 ? argv[2] : "NUL", "w"); if (!g_f) return 90;
    srv_config cfg = { SRV_HTTPS }; srv *s;
    if (strcmp(mode, "dflt") && strcmp(mode, "dfltsamp")) { cfg.io_timeout_ms = 30000; cfg.lifetime_ms = 60000; }
    DWORD tb = GetTickCount();
    int rc = srv_start(&cfg, &s); g_t0 = GetTickCount();
    P("mode=%s srv_start rc=%d took %lu ms", mode, rc, (unsigned long)(g_t0 - tb));
    if (rc) { fclose(g_f); return 91; }
    if (!strcmp(mode, "warmschan")) {
        HMODULE sc = LoadLibraryA("sspicli.dll"); (void)sc;
        PSecurityFunctionTableW (WINAPI *ist)(void) = (void *)GetProcAddress(LoadLibraryA("secur32.dll"), "InitSecurityInterfaceW");
        if (ist) {
            PSecurityFunctionTableW t = ist(); CredHandle ch; TimeStamp ts; SCHANNEL_CRED c; memset(&c, 0, sizeof c);
            c.dwVersion = SCHANNEL_CRED_VERSION; c.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
            SECURITY_STATUS st = t->AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &c, NULL, NULL, &ch, &ts);
            TL("warm schannel outbound cred st=0x%lx", (unsigned long)st);
            if (st == SEC_E_OK) t->FreeCredentialsHandle(&ch);
        }
    }
    if (!strcmp(mode, "warmhttp")) {
        srv *h = srv_http(NULL, 0);
        if (h) { HINTERNET hi = t_inet_open(NULL); char b[256]; size_t l; DWORD e; int st = t_http_get(hi, srv_url(h, "/"), NULL, T_INET_FRESH, b, sizeof b, &l, &e); TL("warm http GET status=%d err=%lu", st, (unsigned long)e); t_inet_close(hi); srv_stop(h); }
    }
    HINTERNET hi = t_inet_open(NULL); TL("InternetOpen -> %p", hi);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0); TL("InternetConnect -> %p", hc);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/x", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0); TL("HttpOpenRequest -> %p", hr);
    t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA | (!strcmp(mode, "ignrev") ? 0x80 : 0));
    TL("HttpSendRequest begin");
    g_main_tid = GetCurrentThreadId(); g_inreq = 1; HANDLE smp = strcmp(mode, "dfltsamp") ? NULL : CreateThread(NULL, 0, sampler, NULL, 0, NULL);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0); DWORD err = ok ? 0 : GetLastError(); g_inreq = 0; g_sampler_stop = 1; if (smp) WaitForSingleObject(smp, 3000);
    TL("HttpSendRequest -> ok=%d err=%lu %s", ok, (unsigned long)err, ok ? "" : t_inet_errname(err));
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi);
    const srv_event *ev; int ne = srv_events(s, &ev);
    for (int i = 0; i < ne; i++) P("   %6lu ms server: conn=%d %s %s", (unsigned long)ev[i].t_ms, ev[i].conn, srv_event_kind_name(ev[i].kind), ev[i].data ? ev[i].data : "");
    P("RESULT mode=%s err=%lu", mode, (unsigned long)err);
    srv_stop(s); fclose(g_f);
    return err ? 1 : 0;
}

static void run_mode(const char *mode, int n) {
    for (int i = 0; i < n; i++) {
        char out[MAX_PATH], extra[MAX_PATH + 32]; snprintf(out, sizeof out, "%sfh_%s_%d.txt", t_tmpdir(), mode, i);
        snprintf(extra, sizeof extra, "%s %s", mode, out);
        DWORD t = GetTickCount(); DWORD code = t_run_child("fh", extra, 120000);
        printf("  PROBE %s #%d uptime=%llu exit=0x%lx child_wall=%lu ms\n", mode, i, (unsigned long long)GetTickCount64(), (unsigned long)code, (unsigned long)(GetTickCount() - t));
        FILE *f = fopen(out, "r"); char l[512];
        if (f) { while (fgets(l, sizeof l, f)) printf("  PROBE %s", l); fclose(f); }
        if (code) t_note("%s #%d failed exit=0x%lx", mode, i, (unsigned long)code);
    }
}

static int slow_children;
static void run_mode_q(const char *mode, int n, const char *label) {   /* quiet: only count slow/failed children */
    int bad = 0, slow = 0;
    for (int i = 0; i < n; i++) {
        char out[MAX_PATH], extra[MAX_PATH + 32]; snprintf(out, sizeof out, "%sfq_%s_%d.txt", t_tmpdir(), mode, i);
        snprintf(extra, sizeof extra, "%s %s", mode, out);
        DWORD t = GetTickCount(); DWORD code = t_run_child("fh", extra, 120000); DWORD w = GetTickCount() - t;
        if (code) bad++; if (w > 1500) slow++;
        if (code || w > 1500) printf("  PROBE %s %s #%d uptime=%llu exit=0x%lx wall=%lu ms\n", label, mode, i, (unsigned long long)GetTickCount64(), (unsigned long)code, (unsigned long)w);
    }
    printf("  PROBE AB %s mode=%s children=%d failed=%d slow(>1.5s)=%d\n", label, mode, n, bad, slow);
}
static void sh(const char *cmd, const char *outname, int maxlines, const char *filter) {
    char full[1024], path[MAX_PATH]; snprintf(path, sizeof path, "%s%s", t_tmpdir(), outname);
    snprintf(full, sizeof full, "cmd /c %s > \"%s\" 2>&1", cmd, path); int rc = system(full);
    printf("  PROBE sh rc=%d: %s\n", rc, cmd);
    FILE *f = fopen(path, "r"); static char l[20000]; int k = 0;
    if (f) { while (fgets(l, sizeof l, f) && k < maxlines) { if (filter && !strstr(l, filter)) continue; l[strcspn(l, "\r\n")] = 0; printf("  PROBE | %.1400s\n", l); k++; } fclose(f); }
}

TEST(fh_probe_first_https_fresh_processes) {
    REQUIRE(U(HttpSendRequestA));
    t_net_prepare();
    printf("  PROBE uptime_ms=%llu\n", (unsigned long long)GetTickCount64());
    sh("wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true", "wev1.txt", 5, NULL);
    run_mode("dfltsamp", 12);   /* first child = the cold first TLS use since boot */
    sh("wevtutil qe Microsoft-Windows-CAPI2/Operational /f:xml /c:600 /rd:false", "wev2.txt", 60, "<EventID>5");
    sh("wevtutil sl Microsoft-Windows-CAPI2/Operational /e:false", "wev3.txt", 5, NULL);
    run_mode_q("dflt", 40, "A baseline");
    sh("reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot /v DisableRootAutoUpdate /t REG_DWORD /d 1 /f", "reg1.txt", 5, NULL);
    run_mode_q("dflt", 40, "B DisableRootAutoUpdate=1");
    sh("reg delete HKLM\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot /v DisableRootAutoUpdate /f", "reg2.txt", 5, NULL);
    run_mode_q("dflt", 40, "C policy removed again");
}
