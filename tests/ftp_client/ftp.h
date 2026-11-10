/* ftp.h - helpers for the ftp_client area (WinINet FTP client against the in-process loopback FTP server).
 *
 * Every test starts its own srv FTP server (common/srv.h), connects with INTERNET_FLAG_PASSIVE unless the test is
 * about active mode, and asserts both the API result and what the client sent on the control connection
 * (srv_ftp_cmd). Transfers use FC_NC (RELOAD | NO_CACHE_WRITE) so the URL cache is neither read nor written.
 * Evidence for each expectation: tests/ftp_client/EVIDENCE.md.
 */
#ifndef FTPC_H
#define FTPC_H
#include "t.h"
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

#define NF(a) ((int)(sizeof(a) / sizeof((a)[0])))
#define FC_NC  (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE)
#define FC_BIN (FTP_TRANSFER_TYPE_BINARY | FC_NC)
#define FC_ASC (FTP_TRANSFER_TYPE_ASCII | FC_NC)

#ifndef ERROR_FTP_TRANSFER_IN_PROGRESS
#define ERROR_FTP_TRANSFER_IN_PROGRESS 12110
#endif
#ifndef ERROR_FTP_DROPPED
#define ERROR_FTP_DROPPED 12111
#endif
#ifndef ERROR_FTP_NO_PASSIVE_MODE
#define ERROR_FTP_NO_PASSIVE_MODE 12112
#endif

typedef struct {
    srv *s;
    HINTERNET hi, hc;
    srv_ftp_config cfg;
    srv_script script;   /* raw servers: must outlive srv_start */
} fcx;

/* Start a server (cfg may be NULL: empty file system). 0 -> t_skip was called, the test must return. */
int  fc_start(fcx *x, const srv_ftp_config *cfg);
/* Raw (non-FTP) scripted server, for misbehaving peers. 0 -> skipped. */
int  fc_start_raw(fcx *x, const srv_step *steps, int nsteps);
/* Open the session handle (t_inet_open: DIRECT, 5 s timeouts) if needed and InternetConnectA to the server.
 * Returns x->hc (NULL on failure; GetLastError preserved). */
HINTERNET fc_connect(fcx *x, const char *user, const char *pass, DWORD flags);
/* fc_start + anonymous passive connect. 0 -> skipped or failed (a failed CHECK is recorded). */
int  fc_open(fcx *x, const srv_ftp_config *cfg);
void fc_end(fcx *x);   /* close handles, stop server */

/* wire (control connection) helpers */
int  fc_ncmd(fcx *x);
const char *fc_cmd(fcx *x, int i);
int  fc_find(fcx *x, const char *prefix, int from);   /* first command at index >= from starting with prefix, -1 */
int  fc_count(fcx *x, const char *prefix);
const char *fc_seq(fcx *x, int from);                 /* "A|B|C" of commands from index from (rotating static) */
int  fc_wait_ncmd(fcx *x, int n, DWORD ms);           /* wait until >= n commands recorded */
int  fc_wait_cmd(fcx *x, const char *prefix, DWORD ms);
void fc_dump(fcx *x);                                  /* t_note every command */

/* InternetGetLastResponseInfoA into a rotating static buffer ("" if none). */
const char *fc_resp(DWORD *err);

/* local scratch files */
const char *fc_local(const char *leaf);               /* unique path in t_tmpdir (rotating static) */
int  fc_put_local(const char *path, const void *p, size_t n);
char *fc_get_local(const char *path, size_t *n);      /* malloc'd, NULL if it cannot be opened */
int  fc_local_exists(const char *path);
void fc_del_local(const char *path);

/* collect a whole listing via FtpFindFirstFileA/InternetFindNextFileA. Returns count, -1 if FindFirst failed
 * (*err = its error). The find handle is closed. */
int  fc_list(fcx *x, const char *pattern, WIN32_FIND_DATAA *out, int cap, DWORD *err);
/* start a server whose LIST output is `listing`, connect, list. 0 -> skipped/failed. */
int  fc_list_raw(const char *listing, const char *pattern, WIN32_FIND_DATAA *out, int cap, int *count, DWORD *err);
const WIN32_FIND_DATAA *fc_by_name(const WIN32_FIND_DATAA *v, int n, const char *name);
void fc_ft_to_st(const FILETIME *ft, SYSTEMTIME *st);

/* read all from a handle into buf (NUL-terminated), returns bytes */
size_t fc_read(HINTERNET h, char *buf, size_t cap, int *ok);

/* common file set */
extern const srv_ftp_file fc_std_files[];
extern const int fc_std_nfiles;
#define FC_STD_CFG { fc_std_files, fc_std_nfiles }
#endif
