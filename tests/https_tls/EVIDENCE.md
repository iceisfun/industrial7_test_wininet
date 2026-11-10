# https_tls: evidence for the expectations

Area prefix `tls_`. All traffic stays on 127.0.0.1 or [::1] and goes to servers the exe starts itself:
- the shared schannel HTTPS server (`common/srv_tls.c`);
- a raw ClientHello observer (`th_*` in `tls_util.c`), which parses SNI, ALPN, extensions and versions, then closes, resets, or sends an alert, plaintext or garbage;
- a CONNECT tunnel proxy (`tp_*`), which records the CONNECT head and relays to the TLS server;
- a minimal schannel server (`mts_*`, `tls_pki_util.c`) serving certificates from the area's own factory: a per-process
  untrusted root ("i7 Test Root <pid>"), leaves it signs (SAN/CN/EKU/validity/hash/key size/CDP/AIA variants), CRLs. Nothing
  is added to any certificate store. Plain-HTTP helper servers (shared library) serve CRLs and the issuer for AIA.

Oracle: Windows 10 22H2 VM (`ver` 10.0.19045.2965, wininet 11.0.19041.2193), boots `tls-20261109-171654-b1` and
`tls2-20261109-175539-b1` (round 1); round 2: `tls4-20261110-050205-b1`, `tls5-20261110-053042-b1`, `tls6-20261110-072756-b1`, `tls7-20261110-090738-b1` (the passing run: 187 tests, 0 failed; output in
`results/win10/https_tls.txt`). The round-1 `tls3` boot never ran (empty serial log), so round 1 ended at boot 2. Decomp: Corpus Explorer, wininet.dll 19041.

Legend:
- **D**: read in the decomp.
- **V**: observed on the Win10 VM. Every hard CHECK in the area passes there.
- **K**: WinINet knowledge, confirmed by **V** before it was promoted to a CHECK.
- **N**: kept as `t_note` only.

## INTERNET_OPTION_SECURITY_FLAGS (31), `tls_secflags.c`
| Fact | Evidence |
|---|---|
| Valid on request handles only. Session and connect handles give 12018 for query and set (A and W). NULL handle gives 12018 | D `InternetQueryOptionA`/`InternetSetOptionA` case 0x1f, V |
| Query with len < 4 or a NULL buffer: 122, `*len = 4`, buffer untouched. A longer buffer returns `*len = 4` | D (generic `LAB_18005a031`), V |
| Set with len < 4: 122. NULL buffer or len 0: 87. len > 4 is accepted | D, V |
| Set ORs `value & 0x13380` into the security-cache entry, so it cannot clear bits and ignores all other bits (32-bit table and combinations) | D (`\|= dw & 0x13380`), V |
| A fresh secure request reads 0 before the send. `INTERNET_FLAG_IGNORE_CERT_CN/DATE_INVALID` are not visible before the send | V (contradicts the guess in 04 F8; F8 measured after success) |
| They are applied at send time. After success the value reads `0x20000000 \| 0x1000/0x2000 \| set bits \| SECURE` | V, 04 F8 |
| After success with 0x100 the value is `0x20000101`. With `SECURITY_SET_MASK` it is `0x20003381` | V |
| After 12045 the value is 0. After 12038 (0x100 set) it is 0x100: no SECURE or STRENGTH bits after a failed verification | V |
| Plain-HTTP request: query gives 0, set gives TRUE with no effect (there is no security entry) | D (`+0x14d0` NULL check), V |
| Flags are per request. A second request on the same connect handle reads 0 and fails with 12045 | V, 04 F9 |
| Private options 98 and 151: request only (else 12018). 151 with len < 4 gives 12010. 98 equals option 31. 151 reads 1 after 12045 | D cases 0x62/0x97, V (151 value: N) |

## Certificate errors, `tls_certerr.c`
| Fact | Evidence |
|---|---|
| Mapping: CERT_E_UNTRUSTEDROOT → 12045, CERT_E_EXPIRED → 12037, CN_NO_MATCH → 12038, WRONG_USAGE and other 0x800B → 12169, SEC_E_* → 12157, CRYPT_E_REVOKED → 12170, CRYPT_E_NO_REVOCATION_CHECK → 0 | D `MapInternetError` |
| LOCALHOST cert: no flags gives 12045. 0x100 gives 200 on 127.0.0.1, localhost and [::1]. CN, DATE, REV and WRONG_USAGE flags without 0x100 still give 12045 | V |
| CN_OTHER: 12045 → (0x100) 12038 → (0x1100) 200. Request flag CN plus 0x100 also gives 200 | V, 04 F8 |
| EXPIRED: 12045 → (0x100) 12037 → (0x2100) 200 | V |
| NO_EKU: 0x100 is enough | V, K |
| CLIENT cert (clientAuth EKU, other CN) as the server cert: 12045 → (0x100) **12169** → (0x1100) 12169 → (0x1300) 200. Wrong usage is reported before the CN mismatch | V |
| A rejected handshake sends no request. A success sends exactly one | V |
| Retry protocol: set the flag on the same handle and resend. A resend without changes repeats the error | V |
| `HttpSendRequestEx` reports 12045 itself. After 0x100 the Ex, Write and End sequence works | V |
| Pooled TLS connection: a new request without flags still fails with 12045 and sends no request | V |
| `InternetErrorDlg(NO_UI\|CHANGE_OPTIONS\|GENERATE_DATA, 12045)` returns 1223 (ERROR_CANCELLED) and changes nothing. A resend still gives 12045. It runs on a worker thread with a 3 s bound | V |
| Revocation (12057/12170) not exercised: needs a CA-issued leaf with a CDP; the shared profiles are self-signed without CDP (04: revocation does not interfere) | N |

## Security information, `tls_info.c`
| Fact | Evidence |
|---|---|
| 32 CERTIFICATE_STRUCT: 64 bytes. ftExpiry = NotAfter and ftStart = NotBefore exactly. Subject and issuer come from CertNameToStrA(SIMPLE\|CRLF\|NO_PLUS) ("localhost", "i7-other.invalid") and are LocalAlloc'd. The protocol, signature and encryption name pointers are NULL. dwKeySize = 256 | D `ConvertSecurityInfoIntoCertInfoStruct`, V |
| 32 with a NULL buffer or len 0: TRUE, len 64. A short buffer (1..63) gives **12004** and len 64 | D, V |
| 32/35/36 on a plain-HTTP request: 12016 (before and after the send) | D (GetSecurityInfo 12004 → 12016), V |
| 32/35/36/66 on an unsent https request succeed: the entry exists from HttpOpenRequest. The struct then has NULL strings and key size 0. 35 already returns a ("Subject...") string | V |
| After a 12045 failure, 32 still describes the server certificate | V |
| 35 string: contains the subject. `*len` = strlen. A too-short buffer gives 122 with `*len = 1` (quirk of the strnlen loop). The W query returns the same **ANSI** bytes, because InternetQueryOptionW has no conversion branch for 35 | D case 0x23, V |
| 36 KEY_BITNESS = 256 = struct dwKeySize = connection info dwCipherStrength. len 3 gives 122/4 | D, V |
| 66 CONNECTION_INFO: needs ≥ 0x2CC (716) or gives 122 with len 0x2CC. After success: fSecure 1, dwProtocol 0x800 (TLS 1.2 client), aiCipher 0x6610, suite 0xC030 named `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, CipherInfo.dwProtocol 0x303. These match the server's own schannel view | D case 0x42, V, 04 F10 |
| 66 on plain HTTP: TRUE with fSecure 0. After a 12045 failure: fSecure 1 and protocol 0 | D (12004 path), V |
| 105 SERVER_CERT_CHAIN_CONTEXT: len ≥ 8 (else 122/8). One element equal to the server cert. Chain TrustStatus: error 0x20 (UNTRUSTED_ROOT), info 0x100. Element: info 0x10c (includes SELF_SIGNED 0x8) | D case 0x69, V |
| 105: the same pointer is returned on each query (one reference per query, freed by the caller). Available after a failure (unverified chain). No chain gives 12019 | D `GetServerCertChain`, V |
| HTTP_PROTOCOL_USED (149): request only. len < 4 gives 12010. 0 before the send and after an HTTP/1.1 exchange | D case 0x95, V |
| INTERNET_OPTION_URL: https scheme from SECURE. Port 443 is omitted. **Port 0 at InternetConnect resolves to 80** even with SECURE on the request | V |

## Handshake wire, broken servers, protocols, `tls_wire.c`
| Fact | Evidence |
|---|---|
| ClientHello: record 0x16/0x0303, legacy_version 0x0303. 21 suites with a host name, 19 with an IP literal; first 0xC02C, 0xC030 offered. Extensions: SNI (host names only), status_request, groups, point formats, sigalgs, session ticket, EMS, renegotiation_info. No supported_versions on this image (TLS 1.2 only) | V |
| SNI: none for 127.0.0.1. `localhost` gives "localhost". The case of the connect host name is preserved ("LocalHost") | V |
| ALPN: absent by default. ENABLE_HTTP_PROTOCOL = HTTP2 on the request handle, or on the session **before** the connect/request handles are created (inherited), adds ALPN "h2,http/1.1" (extension 16 between session_ticket and EMS) when TLS 1.2/1.3 is enabled. On the session **after** the request exists it has no effect (boot 1). Value 1 is masked off | D `SecureNegotiate_Fsm`, option 0x94, V |
| ENABLE_HTTP_PROTOCOL set: len ≠ 4 gives 12010. Bits outside 3 give 87. Session, connect and request handles are accepted. NULL handle gives 12018. Query gives 87 | D, V |
| Against an HTTP/1.1-only TLS server with h2 offered: 200 over HTTP/1.1, PROTOCOL_USED 0 | V |
| Broken peers: FIN after reading the hello → 12029. RST → 12031. Fatal alert, plaintext HTTP or garbage → 12157. Truncated ServerHello then FIN → 12029. FIN without reading → 12030 (timing: 12029/12030/12031 accepted). https to a plain-HTTP server → 12029. http to the TLS server → 12152 | V |
| Server restricted to TLS 1.2 works. TLS 1.0/1.1-only gives 12157 when the client's SecureProtocols lacks them (this image: 0x800; expectation computed from the registry, read only). TLS 1.3-only server credential: 12029 (ASC 0x80090331) | V, D `GetSecureProtocolsSettings` default 0xA80 |
| wininet has no per-handle SECURE_PROTOCOLS option: client versions come from `SecureProtocols` (HKCU, policy), which is only changeable in a dx_ area | D (no option case touches GlobalSecureProtocols) |

## Flows, `tls_flows.c`
| Fact | Evidence |
|---|---|
| Large (200 KB, many records), chunked, close-delimited (close_notify), split/slow and truncated (8 of 16 bytes, ok=TRUE) bodies over TLS. Post body and headers are recorded | V |
| HTTP_DECODING TRUE (request or session) adds no Accept-Encoding, and a gzip body comes back raw (73 bytes) | V (boots 1+2) |
| Request head over TLS = head over plain HTTP (same names and order) | V |
| **No pooling of ignored-cert connections**: three requests on one connect handle, each with 0x100, use three TCP connections and three handshakes. A redirect on the same request handle reuses its connection. `Connection: close` → a new handshake per request | V (boots 1+2) |
| Client cert: a server request without a configured cert gives 12044, even with every ignore flag set and **before** the CA check | V |
| CLIENT_CERT_CONTEXT: request only (12018). len < 0x28 gives 122. NULL/0 gives 87. On a plain-HTTP request: 12046 | D case 0x54, V |
| SELECT_CLIENT_CERT: request only. len < 4 gives 122. 12046 before any list exists. After 12044, index -1 is accepted and the resend succeeds without a cert | D case 0x2f, V |
| A cert set after 12044, or before the send, reaches the server (client_cert=1) | V |
| CONNECT proxy (INTERNET_OPEN_TYPE_PROXY, per session): the exact head is `CONNECT host:port HTTP/1.0`, `User-Agent`, `Host: host:port`, `Content-Length: 0`, `Proxy-Connection: Keep-Alive`, `Pragma: no-cache`. The certificate is checked against the target name (12038 without 0x1000). SNI inside the tunnel is the target. 403/502/407 replies surface as that status with HttpSendRequest TRUE | V |
| Redirects: http→https lands on a new origin with fresh flags (12045, then 0x100 and a resend gives 200, URL updated). https→http is followed silently (no 12040 with NO_UI flags). https→https to another origin: 12045 again even with 0x100 set for the first hop | V |

## Security helper exports, `tls_misc.c`
| Fact | Evidence |
|---|---|
| InternetSecurityProtocolToStringA/W: reserved ≠ 0 or NULL pcch gives 87. Unknown or combined bits give 87 (count untouched). A NULL buffer always gives 122 with len+1. A buffer ≤ strlen gives 122 with len+1. Success writes strlen | D 0x1844f0, V |
| The 7 known bits: 0x2 "PCT 1.0", 0x8 "SSL 2.0", 0x20 "SSL 3.0", 0x80 "TLS 1.0", 0x200 "TLS 1.1", 0x800 "TLS 1.2", 0x2000 "TLS 1.3" (MUI strings, checked only on English UI). W matches A | D (7-entry table), V |
| InternetGetSecurityInfoByURL(A): both out pointers NULL gives 87. A host never contacted gives 12028. After a connect that used ignore flags it is still 12028: VerifyServerCert persists the chain only when flags & 0x7a13180 == 0. The unadorned export equals the A export | D `FindCertEntryInCache`, `VerifyServerCert`, V |
| **The URL buffer is written**: FindCertEntryInCache NULs the host end in place and restores it. A read-only literal crashes with 0xC0000005 (boot 2). Tests pass writable arrays | D, V |

## Issued certificate chains, `tls_pki.c` (mini schannel server, area-made root + leaves)
| Fact | Evidence |
|---|---|
| VerifyTrust passes the request's security flags as the SSL policy's fdwChecks (HTTPSPolicyCallbackData, dwAuthType 2), and the connect host name with **one trailing '.' removed**. Revocation checking (WTD_REVOKE_WHOLECHAIN) when `CertificateRevocation` is set (lab: HKCU 1) and bit 0x800000 is clear | D `CSecureSocket::VerifyTrust` |
| MapInternetError: CRYPT_E_REVOCATION_OFFLINE → 12057, CRYPT_E_REVOKED → 12170, TRUST_E_CERT_SIGNATURE → 12169 (12062 with a weak-signature chain), every other 0x800B.... → 12169 | D `MapInternetError`, `FUN_18010eaca` |
| The schannel server sends only the leaf (the untrusted issuer in its credential store is not sent): the client chain is **partial**. No flags → 12045. 0x100 covers the partial chain, then **12057** for every issued leaf, CDP or not. 0x180 (or SECURITY_SET_MASK) → 200 | V (tls4, tls5) |
| Partial chain status: 0x1010040 (PARTIAL_CHAIN, REVOCATION_STATUS_UNKNOWN, OFFLINE_REVOCATION) on the unverified chain after 12057; only 0x10000 after a 0x180 success. One element | V |
| Security flags after the 0x180 success: 0x20000181. After 12057: 0x100 (no SECURE/strength bits). A resend without changes repeats 12057 | V |
| Errors surface one at a time, in a fixed order: wrong usage 12169 → validity 12037 → name 12038 → revocation 12057. Each flag only removes its own error (table rows in `tls_pki_error_order_*`) | V |
| Retry on one handle: 12045 → (0x100) 12037 → (0x2000) 12038 → (0x1000) 12057 → (0x80) 200; one TCP connection per attempt, one request reaches the server | V |
| Name matching: SAN dns only + IP host → 12038. SAN with only an IP entry: the host name still matches CN (CN fallback). CN-only certificates match by CN (IP literal "127.0.0.1" included). SAN DNS compare is case-insensitive. `*`, `*host`, `local*`, `*.localhost` do not match `localhost`. `localhost.` matches `localhost` | V, D (trailing dot) |
| Validity: not-yet-valid and expired leaves → 12037, cleared by 0x2000 or INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | V |
| EKU: serverAuth, serverAuth+clientAuth, none, anyExtendedKeyUsage accepted; clientAuth or codeSigning only → 12169, cleared by 0x200 | V |
| Hash/key: SHA-1, SHA-384 and RSA-1024 leaves behave like SHA-256 (12057 → 0x180 OK; no 12062 with a partial chain). An MD5-signed leaf fails the handshake: 12157 whatever the flags | V |
| KEY_BITNESS / dwKeySize with an RSA-4096 leaf: 256 (cipher strength, not modulus size) | V, D |
| Option 32 W: InternetQueryOptionW forwards 0x1e..0x2c (except 0x21/0x22/0x29) to the A function, so the W struct returns **ANSI** strings; short buffer 12004 with len 64 | D (W dispatch), V |
| Certificate info for an issued leaf: subject/issuer = CertNameToStrA(SIMPLE\|CRLF\|NO_PLUS) of the leaf, dates = the leaf's | D, V |
| AIA caIssuers URL: CryptoAPI fetches the issuer (`GET /issuer.crt HTTP/1.1`, `Connection: Keep-Alive`, `Accept: */*`, `User-Agent: Microsoft-CryptoAPI/10.0`, `Host`). The chain is then complete: 2 elements, error 0x20 (UNTRUSTED_ROOT), info 0x100; 0x100 → 12057, 0x180 → 200 | V |
| An expired issuer fetched through AIA → 12037 with 0x100 and 0x180; 0x2180 → 200 | V |
| **No CRL is fetched under an untrusted root**, partial or complete chain: CDP to a 404, a closed port, a valid CRL or a CRL revoking the leaf all give 12057 with 0x100 and 200 with 0x180; the CRL server sees no request. 12170 (revoked) needs a trusted root, i.e. a store change (dx_ area) | V |

## Asynchronous mode, `tls_async.c`
| Fact | Evidence |
|---|---|
| HttpSendRequest returns FALSE/ERROR_IO_PENDING; certificate errors (12045, 12038, 12037, 12169), 12044, 12157 (alert, garbage, plaintext) and 12031 arrive as REQUEST_COMPLETE dwResult 0, dwError = the sync error. The retry (set flags, resend) completes with dwResult 1 | V |
| Status sequence, 12045: 80 20 21 50 51 100 (no SENDING_REQUEST/REQUEST_SENT/RECEIVING). Success: 80 20 21 30 31 40 41 100 | V |
| InternetOpenUrl (async, https, untrusted): ERROR_IO_PENDING, completion dwResult 0 / dwError 12045, HANDLE_CREATED seen. HttpSendRequestEx async → 12045 | V |
| Security info options (66, 36, 105) after an async success equal the sync values | V |

## HTTP over TLS, `tls_more.c`
| Fact | Evidence |
|---|---|
| Verb/status table (GET, HEAD, DELETE, OPTIONS, PROPFIND; 200/204/207/299/403/404/410/418/500): status, body (none for HEAD/204), request line and `Host: 127.0.0.1:<port>` identical to plain HTTP | V |
| 300 KB POST body, chunked HttpSendRequestEx upload (the caller's `Transfer-Encoding: chunked` still gets `Content-Length: 0`), 36 KB of request headers across records, 100 KB read via QueryDataAvailable (12 rounds), ReadFileEx over a chunked body | V |
| Six concurrent sessions on threads each complete their own handshake and request | V |
| INTERNET_FLAG_SECURE on InternetConnect (not the request) is ignored: request flags 0x8, URL `http://`, plain HTTP to the TLS port → 12152 | V |
| INTERNET_OPTION_REQUEST_FLAGS: 0x8 before the send, 0x40 after; URL option `https://127.0.0.1:<port>/f` | V (value N for the bit meanings) |
| INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP(S) do not change redirects on this path: https→http is followed (200), http→https lands on the new origin with 12045 | V |
| Setting 0x2000 after a success ORs into the read-back value, the body is unaffected | V |

## Not covered / environment
- 12057 is covered (`tls_pki.c`). 12170 (REVOKED) cannot be produced without trusting the test root (no CRL fetch under an
  untrusted root, VM): needs a dx_ area that adds and removes a root. 12055 SEC_CERT_ERRORS and 12062 WEAK_SIGNATURE come
  from VerifyTrust's multi-error loop, which only runs with an internal socket flag (`this+0x58 & 2`) that no public option was
  found to set; recorded from the decomp only (D).
- Side effects: CryptoAPI may cache the AIA-fetched issuer for the user (URL cache of cryptnet, unique loopback URLs).
- TLS 1.0/1.1/1.3 client behaviour depends on `SecureProtocols` (0x800 on the lab image, 0xA80 by default). The expectations read it (read only). Changing it belongs in a `dx_` area.
- SSL2/SSL3/PCT are not testable: schannel on 19041 refuses them server side.
