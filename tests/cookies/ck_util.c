/* ck_util.c - helpers for the cookies area (see ck.h). No TESTs here. */
#include "ck.h"
#include <stdlib.h>
#include <ctype.h>

static char g_rb[32][1024]; static volatile LONG g_ri;
static char *rbuf(void) { return g_rb[InterlockedIncrement(&g_ri) & 31]; }
static WCHAR g_wb[16][1024]; static volatile LONG g_wi;

const char *ck_host(const char *tag) { return t_uniq_host(tag); }
const char *ck_url(const char *host, const char *path) { char *b = rbuf(); snprintf(b, 1024, "http://%s%s", host, path ? path : "/"); return b; }
const char *ck_surl(const char *host, const char *path) { char *b = rbuf(); snprintf(b, 1024, "https://%s%s", host, path ? path : "/"); return b; }
const char *ck_upath(const char *tag) { char *b = rbuf(); snprintf(b, 1024, "/%s", t_uniq(tag)); return b; }

static const char *k_wd[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const char *k_mon[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
static void st_days(SYSTEMTIME *st, int days) {
    FILETIME ft; ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft); u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    u.QuadPart += (ULONGLONG)((LONGLONG)days * 864000000000LL);
    ft.dwLowDateTime = u.LowPart; ft.dwHighDateTime = u.HighPart; FileTimeToSystemTime(&ft, st);
}
const char *ck_date(int days) {
    SYSTEMTIME st; st_days(&st, days); char *b = rbuf();
    snprintf(b, 1024, "%s, %02u %s %04u %02u:%02u:%02u GMT", k_wd[st.wDayOfWeek], st.wDay, k_mon[st.wMonth - 1], st.wYear, st.wHour, st.wMinute, st.wSecond);
    return b;
}
const char *ck_date_old(int days) {
    SYSTEMTIME st; st_days(&st, days); char *b = rbuf();
    snprintf(b, 1024, "%s, %02u-%s-%04u %02u:%02u:%02u GMT", k_wd[st.wDayOfWeek], st.wDay, k_mon[st.wMonth - 1], st.wYear, st.wHour, st.wMinute, st.wSecond);
    return b;
}
const WCHAR *ck_w(const char *s) {
    WCHAR *b = g_wb[InterlockedIncrement(&g_wi) & 15]; int i = 0;
    for (; s && s[i] && i < 1023; i++) b[i] = (unsigned char)s[i];
    b[i] = 0; return b;
}
const char *ck_a(const WCHAR *s) {
    char *b = rbuf(); int i = 0;
    for (; s && s[i] && i < 1023; i++) b[i] = s[i] < 128 ? (char)s[i] : '?';
    b[i] = 0; return b;
}

/* ---------------------------------------------------------------- cleanup registry */
typedef struct { char *url, *name, *attrs; DWORD flags; } ck_ent;
static ck_ent *g_ck; static int g_nck; static int g_atexit;
static void ck_atexit(void) { ck_cleanup(); }

static char *attr_dup(const char *data, const char *key) {   /* value of "; key=" in a cookie string, or NULL */
    size_t kl = strlen(key);
    for (const char *p = strchr(data, ';'); p; p = strchr(p + 1, ';')) {
        const char *q = p + 1; while (*q == ' ' || *q == '\t') q++;
        if (!_strnicmp(q, key, kl) && (q[kl] == '=' || q[kl] == ' ')) {
            q += kl; while (*q == ' ') q++;
            if (*q != '=') continue;
            q++; while (*q == ' ') q++;
            size_t n = strcspn(q, ";"); while (n && (q[n - 1] == ' ' || q[n - 1] == '\t')) n--;
            char *r = malloc(n + 1); memcpy(r, q, n); r[n] = 0; return r;
        }
    }
    return NULL;
}
void ck_track(const char *url, const char *name, const char *attrs, DWORD flags) {
    if (!g_atexit) { g_atexit = 1; atexit(ck_atexit); }
    g_ck = realloc(g_ck, (g_nck + 1) * sizeof *g_ck);
    g_ck[g_nck].url = _strdup(url); g_ck[g_nck].name = _strdup(name ? name : "");
    g_ck[g_nck].attrs = _strdup(attrs ? attrs : ""); g_ck[g_nck].flags = flags; g_nck++;
}
static void track_data(const char *url, const char *name, const char *data, DWORD flags) {
    char nm[512] = "", attrs[1024] = "";
    if (name) snprintf(nm, sizeof nm, "%s", name);
    else if (data) {
        const char *p = data; while (*p == ' ' || *p == '\t') p++;
        size_t n = strcspn(p, "=;");
        if (p[n] == '=') { while (n && (p[n - 1] == ' ' || p[n - 1] == '\t')) n--; if (n >= sizeof nm) n = sizeof nm - 1; memcpy(nm, p, n); nm[n] = 0; }
    }
    if (data) {
        char *pa = attr_dup(data, "path"), *dm = attr_dup(data, "domain");
        if (pa) { snprintf(attrs + strlen(attrs), sizeof attrs - strlen(attrs), "; path=%s", pa); free(pa); }
        if (dm) { snprintf(attrs + strlen(attrs), sizeof attrs - strlen(attrs), "; domain=%s", dm); free(dm); }
    }
    ck_track(url, nm, attrs[0] ? attrs + 2 : NULL, flags & INTERNET_COOKIE_APPLY_HOST_ONLY);
}
void ck_cleanup(void) {
    __typeof__(&InternetSetCookieExA) p = U(InternetSetCookieExA);
    for (int i = g_nck - 1; i >= 0; i--) {
        if (p) {
            char d[2048];
            snprintf(d, sizeof d, "%s%sx; %s%s%s", g_ck[i].name, g_ck[i].name[0] ? "=" : "", CK_PAST, g_ck[i].attrs[0] ? "; " : "", g_ck[i].attrs);
            p(g_ck[i].url, NULL, d, INTERNET_COOKIE_HTTPONLY | g_ck[i].flags, 0);
        }
        free(g_ck[i].url); free(g_ck[i].name); free(g_ck[i].attrs);
    }
    free(g_ck); g_ck = NULL; g_nck = 0;
}

DWORD ck_setx(const char *url, const char *name, const char *data, DWORD flags, DWORD *gle) {
    __typeof__(&InternetSetCookieExA) p = U(InternetSetCookieExA);
    if (!p) { if (gle) *gle = ERROR_PROC_NOT_FOUND; return 0; }
    if (url && data) track_data(url, name, data, flags);
    SetLastError(0xdeadbeef);
    DWORD r = p(url, name, data, flags, 0);
    if (gle) *gle = GetLastError();
    return r;
}
BOOL ck_set(const char *url, const char *name, const char *data) {
    __typeof__(&InternetSetCookieA) p = U(InternetSetCookieA);
    if (!p) return FALSE;
    if (url && data) track_data(url, name, data, 0);
    return p(url, name, data);
}

DWORD ck_gle, ck_size;
BOOL ck_get(const char *url, const char *name, DWORD flags, char *out, DWORD cap) {
    __typeof__(&InternetGetCookieExA) p = U(InternetGetCookieExA);
    out[0] = 0;
    if (!p) { ck_gle = ERROR_PROC_NOT_FOUND; ck_size = 0; return FALSE; }
    DWORD sz = cap; SetLastError(0xdeadbeef);
    BOOL r = p(url, name, out, &sz, flags, NULL);
    ck_gle = GetLastError(); ck_size = sz;
    if (!r) out[0] = 0;
    return r;
}
const char *ck_gets(const char *url, const char *name, DWORD flags) {
    static char big[8][16384]; static volatile LONG bi;
    char *b = big[InterlockedIncrement(&bi) & 7];
    ck_get(url, name, flags, b, sizeof big[0]);
    return b;
}

int ck_count(const char *s) {
    if (!s || !*s) return 0;
    int n = 1; for (const char *p = s; (p = strstr(p, "; ")); p += 2) n++;
    return n;
}
int ck_index(const char *s, const char *item) {
    if (!s) return -1;
    size_t il = strlen(item); int idx = 0;
    for (const char *p = s; ; idx++) {
        const char *e = strstr(p, "; "); size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n == il && !memcmp(p, item, il)) return idx;
        if (!e) return -1;
        p = e + 2;
    }
}
int ck_has(const char *s, const char *item) { return ck_index(s, item) >= 0; }

int ck_wire_get(HINTERNET session, const char *url, const char *hdrs, DWORD flags) {
    __typeof__(&InternetOpenUrlA) po = U(InternetOpenUrlA);
    __typeof__(&HttpQueryInfoA) pq = U(HttpQueryInfoA);
    if (!po || !pq) return 0;
    HINTERNET h = po(session, url, hdrs, hdrs ? (DWORD)-1 : 0, CK_WIRE_BASE | flags, 0);
    if (!h) return 0;
    DWORD code = 0, sz = sizeof code;
    if (!pq(h, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &code, &sz, NULL)) code = 0;
    char buf[4096]; int ok; t_inet_read_all(h, buf, sizeof buf, &ok);
    t_inet_close(h);
    return (int)code;
}
