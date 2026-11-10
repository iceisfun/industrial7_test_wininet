/* urlcache_enum_groups - helper implementation (see ueg.h). */
#include "ueg.h"
#include <stdlib.h>

FILETIME ueg_ft(ULONGLONG v) { FILETIME f; f.dwLowDateTime = (DWORD)v; f.dwHighDateTime = (DWORD)(v >> 32); return f; }
ULONGLONG ueg_u64(FILETIME f) { return ((ULONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime; }
FILETIME ueg_now(void) { FILETIME f; GetSystemTimeAsFileTime(&f); return f; }
FILETIME ueg_days(int days) { return ueg_ft(ueg_u64(ueg_now()) + (LONGLONG)days * 864000000000LL); }
DWORD ueg_align4(DWORD n) { return (n + 3) & ~3u; }

const WCHAR *ueg_w(const char *s) {
    static WCHAR buf[8][1024]; static int k;
    WCHAR *b = buf[k++ & 7]; int i = 0;
    for (; s && s[i] && i < 1023; i++) b[i] = (unsigned char)s[i];
    b[i] = 0; return b;
}

const char *ueg_url(const char *tag) { return t_uniq_cache_url(tag); }

int ueg_make_entry(const char *url, DWORD type, FILETIME expire, FILETIME lastmod, const char *hdr, const char *ext, const char *body) {
    if (!U(CreateUrlCacheEntryA) || !U(CommitUrlCacheEntryA)) return 0;
    char path[MAX_PATH + 1] = { 0 };
    t_cache_track(url);
    if (!U(CreateUrlCacheEntryA)(url, 0, ext ? ext : "", path, 0)) return 0;
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    const char *b = body ? body : "x"; DWORD w = 0;
    WriteFile(f, b, (DWORD)strlen(b), &w, NULL); CloseHandle(f);
    if (!U(CommitUrlCacheEntryA)(url, path, expire, lastmod, type, (LPBYTE)hdr, hdr ? (DWORD)strlen(hdr) : 0, ext, NULL)) {
        DeleteFileA(path); return 0;
    }
    return 1;
}

int ueg_make_simple(const char *url) { return ueg_make_entry(url, NORMAL_CACHE_ENTRY, ueg_days(30), ueg_days(-1), NULL, "txt", "hello"); }

INTERNET_CACHE_ENTRY_INFOA *ueg_info_a(const char *url, DWORD *size_out) {
    if (!U(GetUrlCacheEntryInfoA)) return NULL;
    DWORD sz = 0;
    if (U(GetUrlCacheEntryInfoA)(url, NULL, &sz) || GetLastError() != ERROR_INSUFFICIENT_BUFFER || !sz || sz > 1 << 20) return NULL;
    INTERNET_CACHE_ENTRY_INFOA *e = calloc(1, sz + 16);
    if (!e) return NULL;
    if (!U(GetUrlCacheEntryInfoA)(url, e, &sz)) { free(e); return NULL; }
    if (size_out) *size_out = sz;
    return e;
}
int ueg_exists(const char *url) { INTERNET_CACHE_ENTRY_INFOA *e = ueg_info_a(url, NULL); free(e); return e != NULL; }

DWORD ueg_expected_size_a(const INTERNET_CACHE_ENTRY_INFOA *e) {
    DWORD n = UEG_ENTRY_A_FIXED;
    if (e->lpszSourceUrlName) n += ueg_align4((DWORD)strlen(e->lpszSourceUrlName) + 1);
    if (e->lpszLocalFileName) n += ueg_align4((DWORD)strlen(e->lpszLocalFileName) + 1);
    if (e->lpszFileExtension) n += ueg_align4((DWORD)strlen(e->lpszFileExtension) + 1);
    if (e->lpHeaderInfo) n += ueg_align4(e->dwHeaderInfoSize);
    return n;
}

int ueg_enum_ex_a(const char *pattern, DWORD flags, DWORD filter, GROUPID gid, ueg_enum_cb cb, void *ctx, DWORD *last_err) {
    if (last_err) *last_err = 0;
    if (!U(FindFirstUrlCacheEntryExA) || !U(FindNextUrlCacheEntryExA) || !U(FindCloseUrlCache)) return -1;
    DWORD cap = 4096; INTERNET_CACHE_ENTRY_INFOA *e = malloc(cap); if (!e) return -1;
    DWORD sz = cap;
    HANDLE h = U(FindFirstUrlCacheEntryExA)(pattern, flags, filter, gid, e, &sz, NULL, NULL, NULL);
    if (!h && GetLastError() == ERROR_INSUFFICIENT_BUFFER && sz > cap && sz < (1u << 20)) {
        free(e); cap = sz; e = malloc(cap); if (!e) return -1;
        sz = cap; h = U(FindFirstUrlCacheEntryExA)(pattern, flags, filter, gid, e, &sz, NULL, NULL, NULL);
    }
    if (!h) { DWORD er = GetLastError(); if (last_err) *last_err = er; free(e); return er == ERROR_NO_MORE_ITEMS ? 0 : -1; }
    int n = 0, go = 1;
    for (;;) {
        n++;
        if (go && cb && !cb(e, sz, ctx)) go = 0;
        if (!go || n >= UEG_ENUM_CAP) break;
        sz = cap;
        if (!U(FindNextUrlCacheEntryExA)(h, e, &sz, NULL, NULL, NULL)) {
            DWORD er = GetLastError();
            if (er == ERROR_INSUFFICIENT_BUFFER && sz > cap && sz < (1u << 20)) {
                free(e); cap = sz; e = malloc(cap); if (!e) break;
                sz = cap;
                if (U(FindNextUrlCacheEntryExA)(h, e, &sz, NULL, NULL, NULL)) continue;
                er = GetLastError();
            }
            if (last_err) *last_err = er;
            break;
        }
    }
    U(FindCloseUrlCache)(h); free(e);
    return n;
}

int ueg_enum_plain_a(const char *pattern, ueg_enum_cb cb, void *ctx, DWORD *last_err) {
    if (last_err) *last_err = 0;
    if (!U(FindFirstUrlCacheEntryA) || !U(FindNextUrlCacheEntryA) || !U(FindCloseUrlCache)) return -1;
    DWORD cap = 4096; INTERNET_CACHE_ENTRY_INFOA *e = malloc(cap); if (!e) return -1;
    DWORD sz = cap;
    HANDLE h = U(FindFirstUrlCacheEntryA)(pattern, e, &sz);
    if (!h && GetLastError() == ERROR_INSUFFICIENT_BUFFER && sz > cap && sz < (1u << 20)) {
        free(e); cap = sz; e = malloc(cap); if (!e) return -1;
        sz = cap; h = U(FindFirstUrlCacheEntryA)(pattern, e, &sz);
    }
    if (!h) { DWORD er = GetLastError(); if (last_err) *last_err = er; free(e); return er == ERROR_NO_MORE_ITEMS ? 0 : -1; }
    int n = 0, go = 1;
    for (;;) {
        n++;
        if (go && cb && !cb(e, sz, ctx)) go = 0;
        if (!go || n >= UEG_ENUM_CAP) break;
        sz = cap;
        if (!U(FindNextUrlCacheEntryA)(h, e, &sz)) {
            DWORD er = GetLastError();
            if (er == ERROR_INSUFFICIENT_BUFFER && sz > cap && sz < (1u << 20)) {
                free(e); cap = sz; e = malloc(cap); if (!e) break;
                sz = cap;
                if (U(FindNextUrlCacheEntryA)(h, e, &sz)) continue;
                er = GetLastError();
            }
            if (last_err) *last_err = er;
            break;
        }
    }
    U(FindCloseUrlCache)(h); free(e);
    return n;
}

typedef struct { const char *url; int exact; int found; } contains_ctx;
static int contains_cb(const INTERNET_CACHE_ENTRY_INFOA *e, DWORD size, void *c_) {
    contains_ctx *c = c_; (void)size;
    if (e->lpszSourceUrlName) {
        if (c->exact ? !lstrcmpiA(e->lpszSourceUrlName, c->url) : strstr(e->lpszSourceUrlName, c->url) != NULL) c->found++;
    }
    return 1;
}
int ueg_enum_contains_a(const char *pattern, DWORD flags, DWORD filter, GROUPID gid, const char *url, int *count) {
    contains_ctx c = { url, 1, 0 };
    int n = ueg_enum_ex_a(pattern, flags, filter, gid, contains_cb, &c, NULL);
    if (count) *count = n;
    return c.found;
}
int ueg_plain_contains_a(const char *pattern, const char *url_substr, int *count) {
    contains_ctx c = { url_substr, 0, 0 };
    int n = ueg_enum_plain_a(pattern, contains_cb, &c, NULL);
    if (count) *count = n;
    return c.found;
}

/* ---------------------------------------------------------------- groups */
static GROUPID g_groups[512]; static int g_ngroups; static int g_atexit;
static void groups_cleanup(void) {
    for (int i = 0; i < g_ngroups; i++)
        if (g_groups[i] && U(DeleteUrlCacheGroup)) U(DeleteUrlCacheGroup)(g_groups[i], CACHEGROUP_FLAG_FLUSHURL_ONDELETE, NULL);
    g_ngroups = 0;
}
void ueg_group_track(GROUPID g) {
    if (!g) return;
    if (!g_atexit) { atexit(groups_cleanup); g_atexit = 1; }
    if (g_ngroups < 512) g_groups[g_ngroups++] = g;
}
void ueg_group_untrack(GROUPID g) { for (int i = 0; i < g_ngroups; i++) if (g_groups[i] == g) g_groups[i] = 0; }
GROUPID ueg_group_new(DWORD flags) {
    if (!U(CreateUrlCacheGroup)) return 0;
    GROUPID g = U(CreateUrlCacheGroup)(flags, NULL);
    if (g && !(flags & CACHEGROUP_FLAG_GIDONLY)) ueg_group_track(g);
    return g;
}
int ueg_groups_contains(GROUPID g, int *count) {
    int n = 0, found = 0;
    if (count) *count = 0;
    if (!U(FindFirstUrlCacheGroup) || !U(FindNextUrlCacheGroup) || !U(FindCloseUrlCache)) return -1;
    GROUPID cur = 0;
    HANDLE h = U(FindFirstUrlCacheGroup)(0, CACHEGROUP_SEARCH_ALL, NULL, 0, &cur, NULL);
    if (!h) return 0;
    do { n++; if (cur == g) found++; } while (n < UEG_ENUM_CAP && U(FindNextUrlCacheGroup)(h, &cur, NULL));
    U(FindCloseUrlCache)(h);
    if (count) *count = n;
    return found;
}
