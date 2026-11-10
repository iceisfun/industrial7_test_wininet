/* Helpers for the gopher_and_stubs area. */
#include "gs.h"

static HINTERNET g_sess;
HINTERNET gs_session(void) {
    if (!g_sess && U(InternetOpenA)) {
        g_sess = U(InternetOpenA)("gs_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (g_sess && U(InternetSetOptionA)) {
            DWORD t = 3000;
            U(InternetSetOptionA)(g_sess, INTERNET_OPTION_CONNECT_TIMEOUT, &t, sizeof t);
            U(InternetSetOptionA)(g_sess, INTERNET_OPTION_RECEIVE_TIMEOUT, &t, sizeof t);
            U(InternetSetOptionA)(g_sess, INTERNET_OPTION_SEND_TIMEOUT, &t, sizeof t);
        }
    }
    return g_sess;
}

HINTERNET gs_connect_http(HINTERNET s) {
    if (!s || !U(InternetConnectA)) return NULL;
    return U(InternetConnectA)(s, "127.0.0.1", 9, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
}

HINTERNET gs_request(HINTERNET c, const char *path) {
    if (!c || !U(HttpOpenRequestA)) return NULL;
    return U(HttpOpenRequestA)(c, "GET", path, NULL, NULL, NULL,
                               INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_COOKIES, 0);
}

typedef struct { gs_fn fn; void *arg; } gs_job;
static DWORD WINAPI gs_job_thread(void *p) { gs_job *j = (gs_job *)p; j->fn(j->arg); return 0; }
int gs_bounded(gs_fn fn, void *arg, DWORD ms) {
    gs_job *j = (gs_job *)malloc(sizeof *j);
    j->fn = fn; j->arg = arg;
    HANDLE h = CreateThread(NULL, 0, gs_job_thread, j, 0, NULL);
    if (!h) { free(j); return 0; }
    DWORD w = WaitForSingleObject(h, ms);
    CloseHandle(h);
    if (w != WAIT_OBJECT_0) { t_note("bounded call did not return within %lu ms - worker thread leaked", ms); return 0; }
    free(j);
    return 1;
}

int gs_module_range(HMODULE h, ULONG_PTR *lo, ULONG_PTR *hi) {
    if (!h) return 0;
    const IMAGE_DOS_HEADER *d = (const IMAGE_DOS_HEADER *)h;
    if (d->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)((const char *)h + d->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    *lo = (ULONG_PTR)h;
    *hi = (ULONG_PTR)h + nt->OptionalHeader.SizeOfImage;
    return 1;
}
