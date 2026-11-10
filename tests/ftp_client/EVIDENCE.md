# ftp_client - evidence

Area: WinINet FTP client (`InternetConnect(INTERNET_SERVICE_FTP)`, `Ftp*`, `InternetFindNextFile`,
`InternetGetLastResponseInfo`, `ftp://` through `InternetOpenUrl`) against the in-process loopback FTP server
(`common/srv_ftp.c`). FTP is enabled in wininet 11.0.19041 on the Win10 22H2 lab image (net_loopback `netlb_ftp_*`
passed there before this area was written), so nothing is skipped for "FTP disabled".

Files: `ftp.h`/`fc_util.c` (helpers, standard file set), `fc_session.c` (login, banners, failures, offline handles,
timeouts), `fc_dirs.c` (PWD/CWD/MKD/RMD/DELE/RNFR+RNTO), `fc_list.c` (LIST wire + UNIX/DOS parser), `fc_xfer.c`
(FtpOpenFile, FtpGetFileSize, FtpGetFile/FtpPutFile, PASV/PORT/EPRT), `fc_cmd.c` (FtpCommand, last response info,
ftp:// URLs).

Legend: **D** = derived from the Win10 wininet decompilation (corpus explorer, function named); **VM** = observed on the
Win10 22H2 guest (wininet 11.0.19041.2193) through `tools/vm_run.sh`; **K** = knowledge only (kept as `t_note`).
Every hard CHECK in the area passed on the VM (see "VM status" below); D-only expectations that the VM contradicted were
changed to the observed value and are listed under "Corrections".

## Login and session (fc_session.c)
| Expectation | Evidence |
|---|---|
| Connect sends only `USER`, `PASS` (no SYST/FEAT/OPTS/PWD) | VM (04 F13) + D `wFtpMakeConnection` |
| NULL/"" user and password -> `USER anonymous`, `PASS <email>` | D `GetEmailNameAndPassword`; email value VM-noted |
| user with NULL/"" password -> `PASS ` (empty) | D `GetEmailNameAndPassword` (`""`) |
| password without user -> 87, no TCP connection | D `GetEmailNameAndPassword` (0x57) |
| NULL/"" server -> 87 | D `FtpConnect` |
| greeting not 2xx (421, 120) -> 12015, nothing sent | D `wFtpMakeConnection` (`GetReply` class != 2 -> 0x2eef) |
| USER 230 -> logged in without PASS; USER 1xx -> 12013 | D `wFtpMakeConnection` |
| USER 5xx -> 12003 (Command fails before the class switch) | D `I_Command` + `wFtpMakeConnection` |
| PASS non-2xx: named user 12014, `anonymous` (any case) 12015 | D `wFtpMakeConnection` (`CompareStringA(NORM_IGNORECASE)`) |
| failed login: no QUIT; last response holds the 5xx text | D `wFtpDisconnect(…,1)` |
| close of the connect handle sends QUIT | D `wFtpDisconnect(…,0)` |
| multi-line replies end at `ddd ` | D `ReceiveFtpResponse` |
| `INTERNET_FLAG_OFFLINE` connect: no TCP; DELE/RNFR/MKD/RMD/PutFile -> 19; FtpCommand -> 12023; FtpOpenFile -> 2 | D `FtpConnect`, `Internal*A`, `InternalFtpCommandA`, `InternalFtpOpenFileA` |
| no listener -> 12029 | VM (research 02) |
| silent peer + 1 s receive timeout -> 12002 | VM |

## Directories and files (fc_dirs.c)
| Expectation | Evidence |
|---|---|
| PWD each call; path between the first `"` and the next unpaired `"`; `""` skipped (does not unescape) | D `wFtpGetCurrentDirectory` |
| 2xx PWD reply without `257 ` -> success with "" | D |
| A: success length = strlen, failure 122 with strlen+1; NULL buffer -> 122 | D `wFtpGetCurrentDirectory` |
| W: success length includes the NUL; 122 reports bytes (chars*2) | D `FtpGetCurrentDirectoryW` |
| CWD/MKD/RMD/DELE: only 2xx succeeds, else 12003; argument sent verbatim | D `wFtp*` + `I_Command` |
| RNFR must be 3xx (else no RNTO, 12003); RNTO must be 2xx | D `wFtpRenameFile` |
| NULL/"" names -> 87 before any traffic | D `Internal*A` |
| NULL handle -> 6; session / HTTP connect handle -> 12018 | D `MapHandleToAddress`, `RIsHandleLocal(FCon)` |

## Listings (fc_list.c)
| Expectation | Evidence |
|---|---|
| FindFirst: `TYPE A`, `PASV`, `LIST [arg]`; arg: none for NULL/""/bare wildcard, directory part for `dir/*.x`, verbatim otherwise | D `wFtpFindFirstFile` + VM |
| one find per session (12110); FindNext past the end -> 18 | D `wFtpFindFirstFile`, `wFtpFindNextFile` |
| NULL lpFindFileData keeps the first entry for FindNext | D `wFtpFindFirstFile` |
| empty listing -> 18; `name: not found`/`cannot find` -> 18; unknown format -> 12003 + listing as response text | D `wFtpFindFirstFile`, `ParseDirList` |
| LIST rejected immediately (no data) -> 12003 | D `I_NegotiateDataConnection` |
| UNIX: `d`->0x10, `-`->0x80, others 0; permission bits as hex nibbles in dwReserved0 (rwxr-xr-x = 0x755); size 64-bit; group column optional; ` -> target` cut for links; trailing spaces kept, name <= 259 chars | D `ParseUnixDirectory`, `ReadUnixPermissions`, `ExtractFileSize`, `_ExtractFilename` |
| UNIX dates: `Mon dd yyyy` -> 00:00; `Mon dd hh:mm` -> current year unless > now+5 days (then year-1); no time-zone conversion; ftCreation/LastAccess zero | D `ExtractUnixDate` |
| DOS: `MM-DD-YY hh:mmAM/PM`, YY<80 -> 20YY, <100 -> 19YY, 4-digit kept; 12AM -> 0; `<DIR>` case-insensitive; dwReserved0 = 0 | D `ParseNtDirectory`, `ExtractNtDate`, `ParseDirList` |
| wildcard filtering on the client, case-insensitive | D `ParseDirList` (`MyFsRtlIsNameInExpression`) + VM |

## Transfers (fc_xfer.c)
| Expectation | Evidence |
|---|---|
| read: `TYPE I|A`, `PASV`, `SIZE name`, `RETR name`; write: no SIZE | VM (netlb) + D `I_NegotiateDataConnection` |
| flags & 3 == 0 -> binary; ==3 -> 87; access must be exactly GENERIC_READ or GENERIC_WRITE | D `InternalFtpOpenFileA` |
| no newline conversion in ASCII mode (either direction) | VM |
| file open blocks every other command (12110) until closed | D `I_Command`, `wFtpOpenFile` |
| write on read handle / read on write handle -> 5 | D `wFtpReadFile`, `wFtpWriteFile` |
| FtpGetFileSize: from `213 n` or from `150 ... (n bytes)`; unknown -> 0xFFFFFFFF + 12028; high part with NULL pointer -> 534; wrong handle 12018 | D `FtpGetFileSize`, `I_NegotiateDataConnection` |
| PASV refused with 425/500/502/530 -> retried in active mode (`TYPE`, `PORT`); other replies -> 12003 | D `I_NegotiateDataConnection`, `I_AttemptDataNegotiation` |
| PASV address must equal the control peer (or both 127.x) | D |
| active mode `PORT h1,h2,h3,h4,p1,p2`; IPv6 control -> `EPRT |2|::1|port|` / `EPSV` | D + VM |
| FtpGetFile: local file created first (CREATE_NEW if fail-if-exists -> 80, no traffic); attributes applied; on failure the local file is deleted (also an overwritten one) | D `InternalFtpGetFileW` |
| FtpPutFile: missing local -> 2 with no traffic; OFFLINE -> 19 | D `InternalFtpPutFileW` |

## FtpCommand, last response, URLs (fc_cmd.c)
| Expectation | Evidence |
|---|---|
| no data: replies 1xx-3xx succeed, 4xx/5xx -> 12003 | D `I_Command` |
| expect response: phFtpCommand NULL -> 87, flags&3 not 1/2 -> 87; data handle is an FTP file handle; RETR gets a SIZE first | D `InternalFtpCommandA`, `I_NegotiateDataConnection` |
| InternetGetLastResponseInfoA: NULL err/len -> 87; NULL buffer or short -> 122 + strlen+1, truncated copy NUL-terminated; success len = strlen; per thread | D `InternetGetLastResponseInfoA` |
| ftp:// file -> FTP file handle; dir -> HTML find handle (`<A HREF=`); RAW_DATA -> plain find handle; `;type=a|i|d`; other `;type=` -> 12005; credentials from URL | D `ParseFtpUrl`, `MakeHtmlDirEntry` + VM |

## Notes only (t_note)
Anonymous password value, EXISTING_CONNECT reuse, peer closes early (error code), unterminated PWD quote, ABOR after an
early read close, INTERNET_OPTION_URL on file handles, RAW_DATA reads, W/A FindNext mixing.

## VM status
See the commit history of this file for each boot; the final status line is recorded below.
