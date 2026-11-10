# https_tls: evidence for the expectations

Area prefix `tls_`. All traffic stays on 127.0.0.1 or [::1] and goes to servers the exe starts itself:
- the shared schannel HTTPS server (`common/srv_tls.c`);
- a raw ClientHello observer (`th_*` in `tls_util.c`), which parses SNI, ALPN, extensions and versions, then closes, resets, or sends an alert, plaintext or garbage;
- a CONNECT tunnel proxy (`tp_*`), which records the CONNECT head and relays to the TLS server.

Oracle: Windows 10 22H2 VM (`ver` 10.0.19045.2965, wininet 11.0.19041.2193), boots `tls-20261109-171654-b1` and
`tls2-*` (see the results file). Decomp: Corpus Explorer, wininet.dll 19041.

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
| 32/35/36/66 on an unsent https request succeed: the entry exists from HttpOpenRequest. The struct then has NULL strings | V |
| After a 12045 failure, 32 still describes the server certificate | V |
| 35 string: contains the subject. `*len` = strlen. A too-short buffer gives 122 with `*len = 1` (quirk of the strnlen loop). The W query returns the same **ANSI** bytes, because InternetQueryOptionW has no conversion branch for 35 | D case 0x23, V |
| 36 KEY_BITNESS = 256 = struct dwKeySize = connection info dwCipherStrength. len 3 gives 122/4 | D, V |
| 66 CONNECTION_INFO: needs ≥ 0x2CC (716) or gives 122 with len 0x2CC. After success: fSecure 1, dwProtocol 0x800 (TLS 1.2 client), aiCipher 0x6610, suite 0xC030 named `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, CipherInfo.dwProtocol 0x303. These match the server's own schannel view | D case 0x42, V, 04 F10 |
| 66 on plain HTTP: TRUE with fSecure 0. After a 12045 failure: fSecure 1 and protocol 0 | D (12004 path), V |
| 105 SERVER_CERT_CHAIN_CONTEXT: len ≥ 8 (else 122/8). One element equal to the server cert. TrustStatus error 0x20 (UNTRUSTED_ROOT), chain info 0x100 | D case 0x69, V |
| 105: the same pointer is returned on each query (one reference per query, freed by the caller). Available after a failure (unverified chain). No chain gives 12019 | D `GetServerCertChain`, V |
| HTTP_PROTOCOL_USED (149): request only. len < 4 gives 12010. 0 before the send and after an HTTP/1.1 exchange | D case 0x95, V |
| INTERNET_OPTION_URL: https scheme from SECURE. Port 443 is omitted. **Port 0 at InternetConnect resolves to 80** even with SECURE on the request | V |

## Handshake wire, broken servers, protocols, `tls_wire.c`
| Fact | Evidence |
|---|---|
| ClientHello: record 0x16/0x0303, legacy_version 0x0303. 21 suites with a host name, 19 with an IP literal; first 0xC02C, 0xC030 offered. Extensions: SNI (host names only), status_request, groups, point formats, sigalgs, session ticket, EMS, renegotiation_info. No supported_versions on this image (TLS 1.2 only) | V |
| SNI: none for 127.0.0.1. `localhost` gives "localhost". The case of the connect host name is preserved ("LocalHost") | V |
| ALPN: absent by default. ENABLE_HTTP_PROTOCOL = HTTP2 on the request handle adds "h2,http/1.1" when TLS 1.2/1.3 is enabled. Value 1 is masked off | D `SecureNegotiate_Fsm`, option 0x94, V (re-measured boot 2) |
| ENABLE_HTTP_PROTOCOL set: len ≠ 4 gives 12010. Bits outside 3 give 87. Session, connect and request handles are accepted. NULL handle gives 12018. Query gives 87 | D, V |
| Against an HTTP/1.1-only TLS server with h2 offered: 200 over HTTP/1.1, PROTOCOL_USED 0 | V |
| Broken peers: FIN after reading the hello → 12029. RST → 12031. Fatal alert, plaintext HTTP or garbage → 12157. Truncated ServerHello then FIN → 12029. FIN without reading → 12030 (timing: 12029/12030/12031 accepted). https to a plain-HTTP server → 12029. http to the TLS server → 12152 | V |
| Server restricted to TLS 1.2 works. TLS 1.0/1.1-only gives 12157 when the client's SecureProtocols lacks them (this image: 0x800; expectation computed from the registry, read only). TLS 1.3-only server credential: 12029 (ASC 0x80090331) | V, D `GetSecureProtocolsSettings` default 0xA80 |
| wininet has no per-handle SECURE_PROTOCOLS option: client versions come from `SecureProtocols` (HKCU, policy), which is only changeable in a dx_ area | D (no option case touches GlobalSecureProtocols) |

## Flows, `tls_flows.c`
| Fact | Evidence |
|---|---|
| Large (200 KB) bodies, chunked, close-delimited (close_notify) and gzip bodies (session-level HTTP_DECODING) over TLS; post body and headers recorded | V |
| Request head over TLS = head over plain HTTP (same names and order) | V |
| Keep-alive: three requests on one connect handle reuse one TLS connection (one TLS_DONE). `Connection: close` → a new handshake per request | V |
| Client cert: a server request without a configured cert gives 12044, even with every ignore flag set and **before** the CA check | V |
| CLIENT_CERT_CONTEXT: request only (12018). len < 0x28 gives 122. NULL/0 gives 87. On a plain-HTTP request: 12046 | D case 0x54, V |
| SELECT_CLIENT_CERT: request only. len < 4 gives 122. 12046 before any list exists. After 12044, index -1 is accepted and the resend succeeds without a cert | D case 0x2f, V |
| A cert set after 12044, or before the send, reaches the server (client_cert=1) | V |
| CONNECT proxy (INTERNET_OPEN_TYPE_PROXY, per session): `CONNECT host:port HTTP/1.0`. The certificate is checked against the target name (12038 without 0x1000). SNI inside the tunnel is the target. 403/502/407 replies surface as that status with HttpSendRequest TRUE | V |
| Redirects: http→https lands on a new origin with fresh flags (12045, then 0x100 and a resend gives 200, URL updated). https→http is followed silently (no 12040 with NO_UI flags). https→https to another origin: 12045 again even with 0x100 set for the first hop | V |
