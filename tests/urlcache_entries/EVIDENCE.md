# urlcache_entries: evidence

Area prefix `uce_`. Files: `uce.h` (helpers), `uce_create.c`, `uce_commit.c`, `uce_info.c`, `uce_retrieve.c`, `uce_keys.c`, `uce_more.c`,
`uce_matrix.c` (table-driven layout/sweep/time/type matrices), `uce_life.c` (lifecycle, streams, threads, prefixed keys,
cross-process), `uce_apimx.c` (every URL-taking entry point x invalid / missing / equivalent / distinct keys).
Oracle: Windows 10 22H2 VM (wininet 11.0.19041.2193) through `tools/vm_run.sh`. Decomp: Win10 reference corpus
(`/api/function/wininet/<name>/decomp`). Every entry uses a unique `wininet<pid>n<seq><tag>.i7test.example` URL and
is deleted by its test. `t_cache_track` is a second, at-exit safety net.

Tags used in the source comments: **[D]** means the expectation comes from the decomp and passed on the VM. **[W10]** means it was
observed on the VM; there the decomp was ambiguous or silent. **[K]** means general WinINet knowledge, also passed on the VM.
Anything still variable is a `t_note`.

## Decomp-grounded (and VM-confirmed)
| Behaviour | Source |
|---|---|
| NULL url -> 87 for every entry point. NULL lpszFileName (Create) -> 87. Info/Retrieve/Stream: non-NULL buffer with NULL size or `*size==0` -> 87. Retrieve/Stream/Unlock `dwReserved!=0` -> 87 | CreateUrlCacheEntryA@0xdca0, CreateUrlCacheEntryExW@0xd180, CommitUrlCacheEntryA/W, GetUrlCacheEntryInfoA@0x1a0c60, RetrieveUrlCacheEntryFileA/W, RetrieveUrlCacheEntryStreamA/W, UnlockUrlCacheEntryFile(A/W) |
| Success sets GetLastError to 0 (`SetLastError(WX_WIN32_FROM_HR(S_OK))`) | all front ends |
| CreateUrlCacheEntry ignores dwReserved; file name `<url leaf stem>[N].<ext>`, N counts up in one directory; no ext -> `name[N]`; ext chars `<>\"/:|?*`, control chars and space -> `_`, trimmed, %-decoded; ext >= 260 chars -> 87; "Cookie:" URLs get a random name | CreateUniqueCacheFile@0xf9bc, _ProcessExtension@0xfd48, _CreateFileWithSuffix@0x10530 |
| http/https keys are parsed: missing `//`, empty host, port > 65535 or non-digit -> 12005; default port (80 http, 443 https) dropped; port re-printed `%d` (`:0080` -> dropped, `:081` -> `:81`); other schemes verbatim; `"http:"` with nothing after the colon is verbatim | ConvertCacheUrlCharToInternal@0x36828, ConvertCacheHttpUrlWCharToInternal@0x34ce0, ReconstructCacheHttpUrlW@0x35550 |
| A keys and the W header are converted with CP_UTF8 | ConvertCacheUrlCharToInternal, CommitUrlCacheEntryW |
| Commit: local file must exist (GetFileAttributesExW error: 2 / 3). A non-EDITED file outside the container -> 87 (VerifyCacheEntryPath). EDITED may be anywhere. Size = file size at commit. Sticky -> exempt delta 86400. Replacing a locked entry -> 32. Replacing an EDITED entry (non-empty file) with a non-EDITED commit -> 32. Old file deleted when the name changes, kept when it is the same name. Hit rate 1 on create, old+1 on replace | CCacheContainer::AddUrl@0x7bef0, VerifyCacheEntryPath@0x1988c, VerifyReplaceEditedEntry@0xcf688 |
| A header: raw bytes, length dwHeaderSize, 0 -> nothing stored. W header: wcslen when 0, stored as UTF-8 | CommitUrlCacheEntryA@0xdaa0 / W@0xd1820 |
| Info A: size = 0x70 + slot(url) + slot(file) + slot(ext) + align4(header), slot = strlen+1 rounded to 4, strings in that order after the struct; *size always gets the requirement (also on success); a too-small buffer is not written; a NULL A buffer is 122 whatever *size says; padding inside the requirement is zeroed; dwStructSize = 0x70 regardless of input; `(NULL, NULL)` is an existence probe -> TRUE | ConvertCacheEntryInfoA@0x92c0 |
| Info W: slots in bytes ((chars+1)*2 rounded to 4); header widened back to UTF-16, dwHeaderInfoSize in characters; NULL buffer with a large-enough *size -> TRUE | ConvertCacheEntryInfoW |
| Ex: lpszRedirectUrl / lpcbRedirectUrl / lpReserved non-NULL -> 87; flag 0x1000 = fixed part only (>= 0x70, NULL buffer -> 87, strings NULL) | GetUrlCacheEntryInfoExA@0x1a0e30, ExW@0xb9c0 |
| SetUrlCacheEntryInfo: fields type/hit rate/4 times/exempt delta, selected by ATTRIBUTE (or 0x1000)/HITRATE/MODTIME/EXPTIME/ACCTIME/SYNCTIME/EXEMPT_DELTA; HEADERINFO_FC masked off; dwStructSize and strings never read; unknown bits ignored; missing -> 2; exempt delta clamped to 86400 and sets STICKY, 0 clears it | SetUrlCacheEntryInfoA@0xcba0, W@0x1a2970, CCacheClientContainer::SetUrlInfo@0xcf34, CCacheContainer::UpdateUrl@0x2ac2c |
| Retrieve: a failed info conversion (122) releases the lock again | RetrieveUrlCacheEntryFileA/W |
| Read/UnlockUrlCacheEntryStream on NULL / stale handle -> 6; stream handles are odd table cookies; read = seek to offset + ReadFile (past EOF -> TRUE, 0 bytes); ReadUrlCacheEntryStreamEx takes a 64-bit offset | ReadUrlCacheEntryStream@0x1a17d0, ReadUrlCacheEntryStreamHelper@0x1ab688, UnlockUrlCacheEntryStreamHelper@0x6f8b0 |
| Delete: missing -> 2; locked -> 32 | DeleteUrlCacheEntry@0x2d3f0 / W@0x21c10, CCacheContainer::DeleteUrl@0x2b350 |
| UnlockUrlCacheEntryFile == UnlockUrlCacheEntryFileA, DeleteUrlCacheEntry == DeleteUrlCacheEntryA (same RVA) | export table |

## VM-observed (the decomp did not settle it)
- The returned CacheEntryType is the committed type ORed with 0x1 (content container flags). Set stores the type verbatim.
- SPARSE entries are hidden from GetUrlCacheEntryInfo (2), but Delete removes them.
- dwUseCount is the live lock count: 0 normally, 1 while retrieved. dwHitRate counts retrievals, 1 -> 2. Get never locks.
- LastAccessTime and LastSyncTime are both the commit time.
- Keys are case-sensitive and stored as typed. That covers scheme, host and path. `HTTP://h/` and `http://h/` are different entries.
  An IDN host is stored in Unicode, not punycode. User info is kept. A `#fragment` is part of the key, and `http://h` gets no `/` appended.
- Deleting a locked entry (file or stream lock) fails with 32, but the delete is remembered: the entry stays visible and readable while
  locked, and the last unlock removes the entry and its file (a later delete gives 2).
  Locks are counted: 2 retrieves need 2 unlocks. Unlocking an unlocked entry succeeds. Unlocking a missing entry gives 2.
- Locks are visible across processes: a child's delete of a parent-locked entry gives 32. A child's lock is released when it exits.
- Retrieve succeeds for an entry with no local file (lpszLocalFileName NULL). It also succeeds when the local file was deleted behind the
  cache's back: the path is stale and there is no file check.
- Create: an empty URL and URLs without a file name get a random 8-char name. Cookie: URLs go to `...\INetCookies\`. CreateUrlCacheEntryExW
  with fPreserveIncomingFileName uses the incoming name and its own extension (`hinted[1].dat`). A leading dot in ext is not doubled.
  The A ext of 299 chars -> 87.
- SetUrlCacheEntryInfo(ATTRIBUTE) stores the type verbatim and ignores locks. Turning EDITED on for an entry committed without it
  makes lpszLocalFileName come back as the bare leaf name: non-EDITED entries store the path relative to the container
  [D AddUrl], and EDITED names are read as absolute. Turning EDITED off restores the full path.
- Retrieve does not change LastAccessTime, and it reports the committed size even after the file grew. SPARSE entries are hidden from
  Retrieve as well (2). Committing a file directly in the container root gives 87, while an upper-case spelling of a valid path is accepted.
- Container: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\IE\<8 chars>\`.

## Pass 3 additions (boots uce5/uce6, 2026-11-10)
Decomp-grounded and VM-confirmed:
- Layout tables over 18 (url, file, ext, header) shapes for A and W: strings in the order url, file, ext, header at the slot offsets of
  ConvertCacheEntryInfoA/W; a NULL ext or file gets no slot; every buffer size in [1, need) -> 122, `*size = need`, buffer untouched.
- Header lengths 1..65000 (A) / 1..16000 (W) round-trip; W headers go to UTF-8 (2-, 3- and 4-byte sequences checked through the A view).
- Every URL-taking entry point (Get A/W/ExA/ExW, Set A/W, Retrieve A/W, Stream A/W, Unlock A/W, Delete A/W, Create W, Commit A/W) gives
  12005 for 15 malformed http(s) keys, 87 for NULL, 2 for missing keys of six shapes. `:80`, `:080`, `:0000080` (http) and `:443`, `:0443`
  (https) all reach the stored key for every operation, including unlock and delete. Scheme/host/path case, fragment, `?`, `:81`, https,
  `//`, `/./`, `%2e`, a trailing host dot and user info are all distinct keys. Non-http keys (ftp, file, private schemes) match byte for byte.
- ReadUrlCacheEntryStream: zero length -> TRUE, 0 bytes; reads past EOF -> TRUE, 0 bytes; backwards and byte-by-byte reads (seek when the
  offset differs); ReadUrlCacheEntryStreamEx with 64-bit offsets; NULL handle -> 6; double unlock / read after unlock -> 6; the last argument
  of ReadUrlCacheEntryStream is ignored; RetrieveUrlCacheEntryStreamA/W dwReserved != 0 -> 87.
- Set: each time flag touches only its field; time, hit-rate, type and exempt-delta tables on W as well as A.
VM-observed:
- Times are stored exactly (no rounding), including 0, 1, 2^63-1 and 0xFFFFFFFFFFFFFFFF.
- A failed RetrieveUrlCacheEntryFile (122) still counts a hit (the entry is found and locked before the conversion fails) but leaves no lock.
  GetUrlCacheEntryInfo never counts. Stream retrieves count like file retrieves.
- Hit rate +1 per retrieve, the returned struct already carries it; use count is the live lock count over nested locks and four threads.
- Stream: an entry with no file -> 3; a deleted file -> 2; a file held open without sharing -> 32; a file whose size changed since commit is
  refused (Retrieve File is not); stream handles are small odd cookies (3, 5, ...), not kernel handles. UnlockUrlCacheEntryFile drops a
  stream's lock too. UnlockUrlCacheEntryStream ignores dwReserved. A child process exiting with a stream open leaves no lock.
- Pending delete (delete of a locked entry -> 32): Retrieve and Set still work on the entry, a replacing commit fails with 32, the last
  unlock removes it and the key is free again.
- Delete while another handle has the file open: the entry is deleted (TRUE), the file stays.
- Two entries may share one local file (no ownership check); deleting the first deletes the file.
- A file created for URL A may be committed for URL B.
- `Visited:` keys go to the history container and `Cookie:` keys to `...\INetCookies\`; their CacheEntryType is exactly the committed
  type (no NORMAL bit ORed in, unlike the content container). Delete removes the cookie file.
- Stream on a file whose size changed -> 13 (ERROR_INVALID_DATA); a same-size rewrite streams the new bytes. A W commit with a malformed
  original URL -> 12005. GetUrlCacheEntryInfoEx ignores unknown flags (0x800 left `*size` untouched in one boot: note), never locks or counts.
  A 122 stream retrieve counts a hit. Cookie: entries can be retrieved.
- CreateUrlCacheEntryExW: the extension argument wins (`hint.dat` + `bin` -> `hint[1].bin`), fPreserveIncomingFileName made no difference for
  these names; NULL ext cuts the last dotted part (`a.b.c` -> `a.b[1]`). URL leaves up to 150 chars keep the stem; 300+ chars get a random
  8-char name. Names are unique across processes (the parent's second suffix was `[3]` in one boot and `[2]` in another: only distinctness is checked).
- An empty extension on commit is stored as "" (not NULL).
Notes only: empty-URL lookups (2 on a fresh profile, environment-dependent), `*size` after Ex flag 0x800, the cross-process suffix number.

## Notes only (t_note)
- File names derived from the URL (table in uce_create_name_from_url; hard-checked by stem) and the unique-path list.

## Not covered (deliberately)
- URL cache enumeration (FindFirstUrlCacheEntry*) and groups/containers belong to other areas.
- HTTP-driven cache population (InternetOpenUrl with caching) belongs to the HTTP cache areas.
- InPrivate / impersonation blocks (BlockCallsInPrivateMode, BlockImpersonatingCaller) need a special process state.
