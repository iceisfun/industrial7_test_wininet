# url_crack: evidence for every expectation

Area: `InternetCrackUrlA/W`, `InternetCreateUrlA/W`, `InternetCanonicalizeUrlA/W`, `InternetCombineUrlA/W`
(wininet.dll 11.0.19041.2193, Windows 10 22H2 19045.2965). Pure string APIs: no network, no registry,
no cache, no cookies, no global state.

Legend: **[D]** read in the decomp served by the Win10 reference corpus (`/api/function/wininet/<name>/decomp`),
**[VM]** observed on the local Win10 22H2 VM (`tools/vm_run.sh`), **[K]** prior knowledge only.
Every hard CHECK in this area is [VM]; most are [D]+[VM]. Knowledge-only and environment-dependent items are
`t_note` or ACP-gated, never plain CHECKs.

## How the tables were made
1. A throw-away probe (not committed) dumped A/W results for ~115 crack URLs x {0, ICU_DECODE, ICU_ESCAPE,
   pointer mode, W}, 67 canonicalize URLs x 13 flag sets, 89 combine pairs x 7 flag sets and 60 create
   component sets on the VM (boot `wnprobe-20261109-171613-b1`), and a second batch (`wnprobe2-*`) for the
   additional vectors.
2. `crack_table.c`, `crack_flags.c`, `canon.c`, `combine.c` were generated from that output and every row was
   cross-read against the decomp below; rows that looked like bugs were checked against the code path that
   produces them before keeping them (see "quirks").
3. The committed exe was run on the VM again; the area passes there (results/win10/url_crack.txt).

## Files
| file | content | evidence |
|---|---|---|
| `uc.h`, `uc.c` | helpers: crack A/W with all buffers, vector checkers, A+W canonicalize/combine/create checkers | - |
| `crack_table.c` | one TEST per URL, checked 4 ways (A/W x with/without extra buffer) | [VM] + [D] CrackUrl@0x60e70, GetUrlAddress@0x61d20 |
| `crack_flags.c` | ICU_DECODE / ICU_ESCAPE tables with explicit lengths | [VM] + [D] _InternetCrackUrlA@0x2dd88 |
| `crack_proto.c` | argument validation, dwStructSize, flags, pointer mode, buffer protocol, dwUrlLength, long URLs | [D] + [VM] |
| `crack_inplace.c` | A decodes %XX in the authority in the caller's buffer | [D] + [VM] |
| `canon.c` | InternetCanonicalizeUrl: protocol + one TEST per URL with every ICU_* flag | [D] wrapper, [VM] shlwapi results |
| `combine.c` | InternetCombineUrl: protocol + one TEST per (base, relative) pair | [D] wrapper, [VM] shlwapi results |
| `create.c` | InternetCreateUrl: ports, userinfo, schemes, escaping, W length protocol, round trip | [D] _InternetCreateUrlA@0x61380, InternetCreateUrlW@0x607f0 + [VM] |

## InternetCrackUrlA/W
- [D][VM] `lpszUrl == NULL` or `lpUrlComponents == NULL` -> 87, A and W.
- [D][VM] A: `dwStructSize != 0x68` -> 87 (0, 1, 0x60, 0x67, 0x69, 0x100, ~0). W: never read; success writes 0x68.
- [D][VM] dwFlags: `(flags & 0x6fffffff) != 0` -> 87; ICU_DECODE/ICU_ESCAPE need at least one component with a
  non-NULL pointer AND nonzero length, else 87 (pointer mode alone is not enough).
- [D][VM] per component: buffer `len <= needed` -> `*len = needed + 1`, call fails 122 AFTER all components are
  processed (the ones that fit are copied); first char of every supplied buffer is cleared on entry; on a parse
  error lengths are untouched.
- [D][VM] W too small: the inner A call gets `(len+1)*3`-byte buffers; when it fails with 122 the W wrapper copies
  no length back (`dwHostNameLength` stays 3). When the inner call fits but the UTF-16 copy-back does not, the
  result is recorded with `t_note` only.
- [D][VM] pointer mode (NULL pointer, nonzero length): pointer into the caller's string (W: WCHAR offsets, mapped
  back by FixStrings), length without NUL; absent components -> NULL/0; file: paths are the raw URL path.
- [D][VM] the path is split at the first `?` or `#` only when an extra-info buffer/length is supplied.
- [D][VM] nPort: explicit decimal wins (`:0` -> 0, `:0080` -> 80); empty -> default; >65535, sign, space,
  letters -> 12005. Defaults ftp 21, http 80, https 443, others 0.
- [D][VM] nScheme table (case-insensitive): ftp 1, gopher 2, http 3, https 4, file 5, news 6, mailto 7, socks 8,
  javascript 9, vbscript 10, res 11, else -1. No `:` -> 12006.
- [VM] hierarchical schemes without `//` -> 12006 (`http:`, `http:/x`, `http:x`, `file:C:/x`, `file:/C:/x`);
  `mailto://`, `javascript://`, `socks://` -> 12006; empty host `http:///p` -> 12005; `[` without `]` and
  `http://::1/` -> 12005; `user:pa:ss@` -> 12005.
- [VM] mailto/javascript/vbscript are cracked as user@host / host with an empty path; news: and unknown schemes
  without `//` are opaque; `":"` alone succeeds with every component empty (nScheme not pinned).
- [D][VM] file: path through PathCreateFromUrlW: `file:///C:/a` and `file://C:/a` -> `C:\a`, `file:///C|/` ->
  `C:\`, `file://server/share` -> `\\server\share`, `file://localhost/C:/x` -> `C:\x`, `%20` decoded; the query is
  dropped from the path when no extra buffer is supplied.
- [D][VM] ICU_DECODE: UrlUnescapeA in place on path/extra after the lengths are stored -> lengths are the
  ESCAPED lengths. ICU_ESCAPE: DecodeUrlInSitu before the split -> decoded lengths, `%3F` then splits.
- [D][VM] **quirk** ICU_ESCAPE + file: URL with an escape: stale tail (`C:\dir sp\file.txtxt`, 20).
- [D][VM] **quirk** A, dwFlags 0: user/password/host %XX are decoded in place in the caller's string
  (`http://us%40er:pa%3Ass@host/` -> buffer `http://us@erer:pa:ssss@host/`); a read-only literal crashes with
  0xC0000005 (seen in the first probe). With ICU_DECODE/ICU_ESCAPE a private copy is used; W always copies.
- [VM] W: lengths are characters; non-ASCII host/path round-trip (`h\u00e9st.example` = 12).
- [VM] 65000-char path and 3000-char host crack fine.

## InternetCreateUrlA/W
- [D][VM] NULL components, NULL length, `dwStructSize != 0x68` (A and W) -> 87; flags other than ICU_ESCAPE,
  ICU_USERNAME, 0x2000 -> 87; password without user name -> 87; nScheme -1 without scheme string, 12, -2 -> 87.
- [D][VM] NULL buffer zeroes `*len` -> 122 + required bytes incl. NUL (A) / x2 bytes (W).
- [D][VM] A too small: 122 + bytes incl. NUL, buffer untouched; success: chars without NUL.
- [D][VM] W too small: `(len+1)*2`-byte inner buffer; inner failure -> need x2 (incl. NUL), copy-back failure ->
  length x2 without NUL (len 3 -> 24, len 9..11 -> 22 for an 11-char URL).
- [D][VM] port written iff `nPort != default(scheme)`: http + nPort 0 gives `:0`.
- [D][VM] opaque schemes: `scheme:` + path, no `/`; the size query counts one extra byte for the `/` it does not
  write (CREATE_Q).
- [D][VM] host with >= 2 `:` and not bracketed -> `[...]`.
- [D][VM] ICU_ESCAPE: path and extra escaped (space, unsafe, `%`, >= 0x80; upper-case hex); userinfo untouched.
  0x2000: user/password escaped (upper-case hex, `:` kept in the password).
- [VM, ACP 1252] W converts components with CP_ACP first: U+00E9 -> `%E9` under ICU_ESCAPE (gated on GetACP()).

## InternetCanonicalizeUrlA/W and InternetCombineUrlA/W
- [D][VM] Canonicalize: NULL url/buffer/length or `*len == 0` -> 87. Combine: NULL base/relative/length -> 87,
  NULL buffer is a size query.
- [D][VM] flags passed as `flags ^ ICU_NO_ENCODE | 0x80000000` to UrlCanonicalize/UrlCombine: escaping on by
  default, ICU_ESCAPE has no effect, unknown bits accepted.
- [D][VM] E_POINTER -> 122 with the required length in characters incl. NUL (A and W).
- [VM] every row in the canon/combine tables (shlwapi behaviour as wininet calls it).
- [VM, ACP 1252] W canonicalize escapes U+00E9 as `%E9` (gated on GetACP()).

## Pass 2 (widening): files and evidence
Probe boot `ucprobe3-20261110-054841-b1` dumped A/W results for 228 more crack URLs (flags 0 / ICU_DECODE / ICU_ESCAPE,
with and without an extra buffer), 109 canonicalize inputs x 16 flag sets, 124 combine pairs x 9 flag sets, 67 create
component sets and ~460 hand experiments; the generator (throw-away, not committed) emitted the tables below and flagged
every row where A and W disagree or a reported length differs from the string. Those rows were split into A-only/W-only
rows or moved to hand-written, ACP-gated tests.

| file | content | evidence |
|---|---|---|
| `crack_table2.c` | 230 rows: ws/wss/ldap/telnet/nntp/rtsp/data/urn/tel/sip/ms-settings/view-source/mk/its, upper-case schemes, gopher ports, port edge cases, userinfo with `@ : ; ? # /` and escapes, IPv6 forms, host forms, query/fragment splits, control characters, file:, mailto:, news:, javascript:, res:, opaque/unknown schemes | [VM] + [D] CrackUrl@0x60e70 |
| `crack_flags2.c` | every pass-2 URL whose result changes under ICU_DECODE / ICU_ESCAPE, A and W, with lengths | [VM] + [D] _InternetCrackUrlA |
| `canon2.c` | 109 inputs x 16 flag sets (incl. DECODE\|ENCODE_PERCENT, BROWSER_MODE\|DECODE, NO_META\|DECODE) | [VM] shlwapi results, [D] wrapper |
| `combine2.c` | 124 pairs x 9 flag sets | [VM], [D] wrapper |
| `create2.c` | 67 component sets: per-scheme default ports, opaque schemes (CREATE_Q), scheme string vs nScheme precedence, userinfo with 0x2000, ICU_ESCAPE, host forms | [VM] + [D] _InternetCreateUrlA |
| `crack_wrapper.c` | W wrapper mechanics, A/W component boundary matrices, ACP retry, pointer mode with escapes, dwUrlLength extremes and sweep, Create/Canonicalize/Combine buffer sweeps, long inputs | [D] InternetCrackUrlW@0x2d690, FixStrings@0x2dc98, InternetCreateUrlW + [VM] |

### Facts added in pass 2
- [D][VM] **W buffer with length 0** is sized from `inetstrlenW(buffer)`: `L"xxxxxxxx"` -> success, length 4, buffer
  NOT written (copy-back with cch 0 only counts); `L""` -> 122, nothing written, nScheme untouched. A with length 0 ->
  122, `*len = 5`, buffer not even cleared. InternetCreateUrlW has the same sizing: `*len 0` + a 63-char buffer ->
  success, 23, nothing written.
- [D][VM] **W failure shape.** Component lengths L with `(L+1)*3 < needed+1` bytes -> the inner A call fails: 122, no
  length changes, no buffer writes, nScheme/nPort untouched. Otherwise FixStrings copies scheme, host, user, password,
  path, extra in order; the first one that does not fit gets its first L characters (no NUL), keeps length L, the call
  fails 122, and later components keep their buffers and lengths. Checked as a 6 x 15 matrix (`crack_wrapper.c`).
- [D][VM] **ACP retry.** %XX bytes that are not UTF-8 (`h%E9st`, `u%E9`, ICU_DECODE/ESCAPE `/%E9`) make FixStrings fail
  with 1113; the copy-back is redone with CP_ACP (U+00E9 under 1252) and the call SUCCEEDS with GetLastError() == 1113
  (the saved error is what SetLastError receives). UTF-8 escapes (`%C3%A9`) need no retry: error 0.
- [VM] W ICU_DECODE lengths: re-counted by MultiByteToWideChar over the A length + 1 bytes, which include the
  stale tail left by in-place unescaping (`/%C3%A9` -> "/\u00e9", length 6; `/%E9` -> "/\u00e9", 4).
- [VM] W pointer mode with escapes: dwFlags 0 -> host/user length is the ESCAPED length (`h%41st` = 6); with ICU_DECODE
  the decoded one (4). A pointer mode decodes the caller's string in place (`http://hAstst/p?q`).
- [D][VM] W `dwUrlLength >= 0x80000000` -> ERROR_NOT_ENOUGH_MEMORY (8): the `(len+1)*3` allocation overflows. A stops
  at the NUL. `dwUrlLength` sweep over `http://u:p@h.x:81/a/b?q#f`: 1..7 -> 12006, `http://u` -> host u,
  `http://u:p` -> 12005, `http://u:p@` -> 12005, a cut port `:8` -> 8; A == W at every length.
- [VM] crack quirks: `http://u?x@h/` -> host `u`, extra `?x@h/` (`?`/`#`/`/` end the authority before `@`);
  `http://user:p@ss@h/` -> password `p`, host `ss@h`; `http://[]/` and `http://[:::]/` accepted; `http://[::1]#f` ->
  12005 while `http://[::1]/?x` is fine; `http://h%2fx/` -> host `h/x`; `res://x.dll:12/a` -> host `x.dll:12`, port 0;
  `file:///C:/a#b` -> path `C:\a#b` AND extra `#b`; `file:///` -> 87; `file://u:p@server/share` -> path
  `u:p@server\share`; `javascript:a:b` -> 12005; mailto: takes a port (`mailto:a@b:25` -> 25); ws/wss/ldap/... are
  unknown (-1) with port 0 unless explicit.
- [VM] canonicalize: `&` is escaped (`%26`), `'` `!` `$` `*` `(` `)` `,` `;` `=` `~` are not; TAB/CR/LF are removed;
  `[`/`]` in the path become `%5B`/`%5D`; `%2e%2e` segments are not dot segments; `x:` -> `file://x:`; `foo:A/../B` ->
  `foo:A%2F..%2FB`; `mailto:a@b?subject=a b` -> `mailto:a@b%3Fsubject=a%20b`.
- [VM] create: SOCKS gives `socks:h:1080/` (no `//`); a scheme string wins over a conflicting nScheme
  (INTERNET_SCHEME_HTTP + "foo" -> `foo://h/x`), and with INTERNET_SCHEME_DEFAULT the string's case is kept
  (`HTTP://h/x`) while the default port is still recognised; an extra without `?`/`#` is appended raw
  (`http://hq`); an empty or NULL host gives `http:///`; a `::`-host is bracketed, a bracketed one is kept.
- [VM] InternetCreateUrlA too small: 122, need incl. NUL, buffer untouched. W: inner failure -> need x2 incl. NUL, buffer
  untouched; copy-back failure -> length x2 WITHOUT the NUL (46 for 23 chars) and the first L chars written.
- [VM] Canonicalize/Combine too small (A and W): 122, need incl. NUL, buffer untouched. 8009-char canonicalize and
  8011-char create succeed (no 2083 limit on these paths).

## Not tested (and why)
- `InternetCheckConnection`: out of scope for this area (network), see the task.
- `DisableUserPswdForHttp` policy (userinfo in http -> 12005): registry policy; would need a dx_ area.
- ICU_USERNAME in InternetCreateUrl: accepted, no observable effect in the vectors tried.
