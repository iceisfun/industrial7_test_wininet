/* uce.h - helpers for the urlcache_entries area (persistent URL cache entry APIs).
 * Area prefix: uce_. Every URL is unique (tmpPrefix + pid + sequence, see t_uniq_host) and every entry created
 * is deleted by the test itself; t_cache_track is a safety net that also deletes it at exit.
 * Struct sizes / offsets are for x64. */
#ifndef UCE_H
#define UCE_H
#include "t.h"
#include <wininet.h>
#include <stdlib.h>
#include "tnet.h"

/* Not in the mingw headers / easier to keep local */
#ifndef CACHE_ENTRY_ATTRIBUTE_FC
#define CACHE_ENTRY_ATTRIBUTE_FC    0x00000004
#define CACHE_ENTRY_HITRATE_FC      0x00000010
#define CACHE_ENTRY_MODTIME_FC      0x00000040
#define CACHE_ENTRY_EXPTIME_FC      0x00000080
#define CACHE_ENTRY_ACCTIME_FC      0x00000100
#define CACHE_ENTRY_SYNCTIME_FC     0x00000200
#define CACHE_ENTRY_HEADERINFO_FC   0x00000400
#define CACHE_ENTRY_EXEMPT_DELTA_FC 0x00000800
#endif

/* x64 layout of INTERNET_CACHE_ENTRY_INFOA/W (decomp ConvertCacheEntryInfoA writes these offsets) */
#define UCE_INFO_SIZE 0x70

/* a unique http URL "http://wininet<pid>n<seq><tag>.i7test.example/<tag>.txt", tracked for cleanup */
static inline const char *uce_url(const char *tag) { return t_uniq_cache_url(tag); }
/* same, as a wide string in a rotating static buffer */
static inline const WCHAR *uce_w(const char *s) {
    static WCHAR b[8][1024]; static LONG n; WCHAR *o = b[InterlockedIncrement(&n) & 7];
    MultiByteToWideChar(CP_ACP, 0, s, -1, o, 1024); return o;
}
static inline const char *uce_a(const WCHAR *s) {
    static char b[8][1024]; static LONG n; char *o = b[InterlockedIncrement(&n) & 7];
    WideCharToMultiByte(CP_ACP, 0, s, -1, o, 1024, NULL, NULL); return o;
}
static inline FILETIME uce_ft(ULONGLONG v) { FILETIME f; f.dwLowDateTime = (DWORD)v; f.dwHighDateTime = (DWORD)(v >> 32); return f; }
static inline ULONGLONG uce_u64(FILETIME f) { return ((ULONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime; }
static inline ULONGLONG uce_now(void) { FILETIME f; GetSystemTimeAsFileTime(&f); return uce_u64(f); }
#define UCE_DAY  (864000000000ULL)
#define UCE_SEC  (10000000ULL)
static const FILETIME uce_zero_ft;

/* write bytes into a file (create/truncate). TRUE on success */
static inline BOOL uce_write_file(const char *path, const void *data, DWORD len) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD w = 0; BOOL ok = len ? WriteFile(h, data, len, &w, NULL) && w == len : TRUE;
    CloseHandle(h); return ok;
}
static inline BOOL uce_write_fileW(const WCHAR *path, const void *data, DWORD len) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD w = 0; BOOL ok = len ? WriteFile(h, data, len, &w, NULL) && w == len : TRUE;
    CloseHandle(h); return ok;
}
/* read a whole small file; returns bytes or -1 */
static inline int uce_read_file(const char *path, char *buf, int cap) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD r = 0; BOOL ok = ReadFile(h, buf, (DWORD)cap, &r, NULL); CloseHandle(h);
    return ok ? (int)r : -1;
}
static inline BOOL uce_file_exists(const char *p) { return GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES; }
static inline BOOL uce_file_existsW(const WCHAR *p) { return GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES; }

/* CreateUrlCacheEntryA + write content + CommitUrlCacheEntryA. path (MAX_PATH) receives the local file, may be NULL.
 * content NULL -> commit with no local file at all. Returns the Commit result; *err = GetLastError of the failing step. */
static inline BOOL uce_make_ex(const char *url, const char *ext, const void *content, DWORD len, DWORD type,
                               const char *hdr, FILETIME expire, FILETIME lastmod, char *path, DWORD *err) {
    char local[MAX_PATH] = ""; DWORD e = 0;
    if (content) {
        if (!U(CreateUrlCacheEntryA)(url, len, ext, local, 0)) { e = GetLastError(); if (err) *err = e; return FALSE; }
        if (!uce_write_file(local, content, len)) { if (err) *err = 0xFFFFFFFF; return FALSE; }
    }
    BOOL ok = U(CommitUrlCacheEntryA)(url, content ? local : NULL, expire, lastmod, type,
                                      (BYTE *)hdr, hdr ? (DWORD)strlen(hdr) : 0, ext, NULL);
    e = GetLastError();
    if (!ok && content) DeleteFileA(local);
    if (path) strcpy(path, local);
    if (err) *err = ok ? 0 : e;
    return ok;
}
static inline BOOL uce_make(const char *url, const char *content, char *path) {
    return uce_make_ex(url, "txt", content, content ? (DWORD)strlen(content) : 0, NORMAL_CACHE_ENTRY, NULL,
                       uce_zero_ft, uce_zero_ft, path, NULL);
}

/* GetUrlCacheEntryInfoA into a malloc'd buffer (free()). NULL on failure, *err = GetLastError */
static inline INTERNET_CACHE_ENTRY_INFOA *uce_info(const char *url, DWORD *size, DWORD *err) {
    DWORD sz = 0; if (err) *err = 0;
    SetLastError(0xdeadbeef);
    if (U(GetUrlCacheEntryInfoA)(url, NULL, &sz)) { if (err) *err = 0xFFFFFFFE; return NULL; }
    DWORD e = GetLastError(); if (e != ERROR_INSUFFICIENT_BUFFER) { if (err) *err = e; return NULL; }
    INTERNET_CACHE_ENTRY_INFOA *p = (INTERNET_CACHE_ENTRY_INFOA *)calloc(1, sz + 16);
    DWORD sz2 = sz;
    if (!U(GetUrlCacheEntryInfoA)(url, p, &sz2)) { if (err) *err = GetLastError(); free(p); return NULL; }
    if (size) *size = sz;
    return p;
}
static inline INTERNET_CACHE_ENTRY_INFOW *uce_infoW(const WCHAR *url, DWORD *size, DWORD *err) {
    DWORD sz = 0; if (err) *err = 0;
    SetLastError(0xdeadbeef);
    if (U(GetUrlCacheEntryInfoW)(url, NULL, &sz)) { if (err) *err = 0xFFFFFFFE; return NULL; }
    DWORD e = GetLastError(); if (e != ERROR_INSUFFICIENT_BUFFER) { if (err) *err = e; return NULL; }
    INTERNET_CACHE_ENTRY_INFOW *p = (INTERNET_CACHE_ENTRY_INFOW *)calloc(1, sz + 16);
    DWORD sz2 = sz;
    if (!U(GetUrlCacheEntryInfoW)(url, p, &sz2)) { if (err) *err = GetLastError(); free(p); return NULL; }
    if (size) *size = sz;
    return p;
}
/* entry present? (GetUrlCacheEntryInfoA(url, NULL, NULL) is an existence probe: decomp GetUrlCacheEntryInfoA) */
static inline BOOL uce_exists(const char *url) { return U(GetUrlCacheEntryInfoA)(url, NULL, NULL); }
static inline BOOL uce_del(const char *url) { return U(DeleteUrlCacheEntryA)(url); }

/* strlen+1 rounded up to 4 (ConvertCacheEntryInfoA string slot) */
static inline DWORD uce_slot(size_t n) { return (DWORD)((n + 4) & ~3u); }
static inline DWORD uce_slotw(size_t n) { return (DWORD)(((n + 1) * 2 + 3) & ~3u); }

/* does p lie inside [base, base+size)? */
static inline int uce_inside(const void *p, const void *base, size_t size) {
    return (const char *)p >= (const char *)base && (const char *)p < (const char *)base + size;
}
/* the cache container directory part of a local file path (up to and including the last backslash) */
static inline void uce_dirname(const char *path, char *out) {
    strcpy(out, path); char *s = strrchr(out, '\\'); if (s) s[1] = 0; else out[0] = 0;
}
#endif
