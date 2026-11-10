/* srv_ftp.c - small scripted FTP server (control + PASV/EPSV/PORT/EPRT data connections) over loopback.
 * One control connection = one session. Files live in an in-memory table (initialised from srv_ftp_config,
 * mutated by STOR/APPE/DELE/MKD/RMD/RNFR+RNTO). Every command line is recorded (SRV_EV_FTP_CMD). */
#include "srv_int.h"

typedef struct { char *path; char *data; long n; int dir; char mdtm[16]; } ftp_ent;
struct srv_ftp_state { ftp_ent *e; int ne, cap; int *ov_used; };

static ftp_ent *find_ent(srv_ftp_state *f, const char *path) {
    for (int i = 0; i < f->ne; i++) if (!strcmp(f->e[i].path, path)) return &f->e[i];
    return NULL;
}
static ftp_ent *add_ent(srv_ftp_state *f, const char *path) {
    ftp_ent *e = find_ent(f, path);
    if (e) return e;
    if (f->ne == f->cap) { f->cap = f->cap ? f->cap * 2 : 16; f->e = realloc(f->e, f->cap * sizeof *f->e); }
    e = &f->e[f->ne++]; memset(e, 0, sizeof *e); e->path = strdup(path); strcpy(e->mdtm, "20200102030405");
    return e;
}
static void del_ent(srv_ftp_state *f, ftp_ent *e) {
    free(e->path); free(e->data); *e = f->e[--f->ne];
}
/* normalise an absolute path: collapse //, ., ..; no trailing slash except root */
static void norm(char *p) {
    char out[1024]; size_t o = 0; const char *s = p;
    out[o++] = '/';
    while (*s) {
        while (*s == '/') s++;
        if (!*s) break;
        const char *e = strchr(s, '/'); size_t l = e ? (size_t)(e - s) : strlen(s);
        if (l == 1 && s[0] == '.') {}
        else if (l == 2 && s[0] == '.' && s[1] == '.') { if (o > 1) { o--; while (o > 1 && out[o - 1] != '/') o--; } }
        else { if (o > 1 && out[o - 1] != '/') out[o++] = '/'; if (o + l < sizeof out - 2) { memcpy(out + o, s, l); o += l; } }
        s += l;
    }
    if (o > 1 && out[o - 1] == '/') o--;
    out[o] = 0; strcpy(p, out);
}
static void resolve(const char *cwd, const char *arg, char *out, size_t cap) {
    if (!arg || !*arg) snprintf(out, cap, "%s", cwd);
    else if (arg[0] == '/') snprintf(out, cap, "%s", arg);
    else snprintf(out, cap, "%s/%s", cwd, arg);
    norm(out);
}
static const char *parent_of(const char *path, char *buf) {
    strcpy(buf, path); char *sl = strrchr(buf, '/');
    if (sl == buf) buf[1] = 0; else if (sl) *sl = 0;
    return buf;
}
static int is_dir(srv_ftp_state *f, const char *p) { if (!strcmp(p, "/")) return 1; ftp_ent *e = find_ent(f, p); return e && e->dir; }
static int wild(const char *pat, const char *s) {
    if (!*pat) return !*s;
    if (*pat == '*') return wild(pat + 1, s) || (*s && wild(pat, s + 1));
    if (*s && (*pat == '?' || tolower((unsigned char)*pat) == tolower((unsigned char)*s))) return wild(pat + 1, s + 1);
    return 0;
}

int srv_ftp_init(srv *s) {
    const srv_ftp_config *fc = s->cfg.ftp;
    srv_ftp_state *f = calloc(1, sizeof *f);
    for (int i = 0; fc && i < fc->nfiles; i++) {
        char p[1024]; snprintf(p, sizeof p, "%s", fc->files[i].path); size_t l = strlen(p);
        int dir = fc->files[i].n < 0 || (l > 1 && p[l - 1] == '/');
        norm(p);
        ftp_ent *e = add_ent(f, p); e->dir = dir;
        if (fc->files[i].mdtm) snprintf(e->mdtm, sizeof e->mdtm, "%s", fc->files[i].mdtm);
        if (!dir) {
            e->n = fc->files[i].n; e->data = malloc(e->n + 1);
            for (long k = 0; k < e->n; k++) e->data[k] = fc->files[i].data ? fc->files[i].data[k] : (char)srv_pattern_byte(k);
            e->data[e->n] = 0;
        }
    }
    /* implicit parent directories */
    for (int i = 0; i < f->ne; i++) {
        char par[1024], tmp[1024]; strcpy(tmp, f->e[i].path);
        for (int d = 0; d < 32; d++) { parent_of(tmp, par); if (!strcmp(par, "/") || !strcmp(par, tmp)) break; if (!find_ent(f, par)) { ftp_ent *e = add_ent(f, par); e->dir = 1; } strcpy(tmp, par); }
    }
    if (fc && fc->noverrides) f->ov_used = calloc(fc->noverrides, sizeof(int));
    s->ftp = f;
    return SRV_OK;
}
void srv_ftp_free(srv *s) {
    srv_ftp_state *f = s->ftp; if (!f) return;
    for (int i = 0; i < f->ne; i++) { free(f->e[i].path); free(f->e[i].data); }
    free(f->e); free(f->ov_used); free(f); s->ftp = NULL;
}
const char *srv_ftp_file_data(srv *s, const char *path, long *n) {
    if (!s || !s->ftp) return NULL;
    char p[1024]; snprintf(p, sizeof p, "%s", path); norm(p);
    EnterCriticalSection(&s->cs);
    ftp_ent *e = find_ent(s->ftp, p);
    const char *d = NULL;
    if (e && !e->dir) { d = malloc(e->n + 1); memcpy((char *)d, e->data, e->n + 1); if (n) *n = e->n; }
    LeaveCriticalSection(&s->cs);
    if (d) srv_keep(s, (void *)d);
    return d;
}
int srv_ftp_cmd_count(srv *s) { int n; if (!s) return 0; EnterCriticalSection(&s->cs); n = s->nftpcmd; LeaveCriticalSection(&s->cs); return n; }
const char *srv_ftp_cmd(srv *s, int i) {
    const char *r = NULL; if (!s) return NULL;
    EnterCriticalSection(&s->cs); if (i >= 0 && i < s->nftpcmd) r = s->ftpcmd[i]; LeaveCriticalSection(&s->cs);
    return r;
}

/* ------------------------------------------------------------------ session */
typedef struct {
    char cwd[1024]; SOCKET pasv; int have_port; unsigned char port_addr[16]; int port_af; unsigned short port_port;
    char rnfr[1024]; long rest; char type;
} ftp_sess;

static int reply(srv_conn *c, const char *fmt, ...) {
    char t[2048]; va_list a; va_start(a, fmt); int n = vsnprintf(t, sizeof t - 3, fmt, a); va_end(a);
    if (n < 0) n = 0; if (n > (int)sizeof t - 3) n = sizeof t - 3;
    if (n < 2 || t[n - 2] != '\r' || t[n - 1] != '\n') { t[n++] = '\r'; t[n++] = '\n'; }
    int r = srv_io_send(c, t, n);
    if (!r) srv_record(c->s, SRV_EV_SENT, c->id, -1, t, n);
    return r;
}
static int read_line(srv_conn *c, char *out, size_t cap) {
    for (;;) {
        char *lf = memchr(c->in, '\n', c->nin);
        if (c->in && lf) {
            size_t l = lf - c->in, k = l; if (k && c->in[k - 1] == '\r') k--;
            if (k >= cap) k = cap - 1;
            memcpy(out, c->in, k); out[k] = 0; srv_io_consume(c, l + 1); return 1;
        }
        if (c->nin > 8192) { c->nin = 0; return 0; }
        if (srv_io_fill(c) <= 0) return 0;
    }
}
static SOCKET open_data(srv_conn *c, ftp_sess *fs) {
    srv *s = c->s; SOCKET d = INVALID_SOCKET;
    if (fs->pasv != INVALID_SOCKET) {
        d = srv_accept_bounded(s, &fs->pasv, 1, 5000);
        SWS.closesocket(fs->pasv); fs->pasv = INVALID_SOCKET;
    } else if (fs->have_port) {
        d = SWS.socket(fs->port_af, SOCK_STREAM, IPPROTO_TCP);
        if (d != INVALID_SOCKET) {
            int r;
            if (fs->port_af == AF_INET) { struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = srv_htons(fs->port_port); memcpy(&a.sin_addr, fs->port_addr, 4); r = SWS.connect(d, (struct sockaddr *)&a, sizeof a); }
            else { struct sockaddr_in6 a; memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_port = srv_htons(fs->port_port); memcpy(&a.sin6_addr, fs->port_addr, 16); r = SWS.connect(d, (struct sockaddr *)&a, sizeof a); }
            if (r) { SWS.closesocket(d); d = INVALID_SOCKET; }
        }
        fs->have_port = 0;
    }
    if (d != INVALID_SOCKET) srv_set_timeouts(d, s->cfg.io_timeout_ms);
    return d;
}
static void close_data(SOCKET d) {
    SWS.shutdown(d, SD_SEND);
    DWORD to = 500; SWS.setsockopt(d, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof to);
    char b[256]; for (int g = 0; g < 8 && SWS.recv(d, b, sizeof b, 0) > 0; g++) ;
    SWS.closesocket(d);
}
static int data_send(SOCKET d, const char *p, size_t n) {
    while (n) { int k = SWS.send(d, p, n > 65536 ? 65536 : (int)n, 0); if (k <= 0) return -1; p += k; n -= k; }
    return 0;
}
static const char *mon(const char *mdtm) {
    static const char *m[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    int mm = (mdtm[4] - '0') * 10 + (mdtm[5] - '0');
    return mm >= 1 && mm <= 12 ? m[mm - 1] : "Jan";
}
static void list_line(char **buf, size_t *n, ftp_ent *e, int names_only) {
    const char *name = strrchr(e->path, '/'); name = name ? name + 1 : e->path;
    char t[1400];
    int k = names_only ? snprintf(t, sizeof t, "%s\r\n", name)
        : snprintf(t, sizeof t, "%s   1 owner    group    %10ld %s %.2s  %.4s %s\r\n", e->dir ? "drwxr-xr-x" : "-rw-r--r--",
                   e->dir ? 0L : e->n, mon(e->mdtm), e->mdtm + 6, e->mdtm, name);
    *buf = realloc(*buf, *n + k + 1); memcpy(*buf + *n, t, k + 1); *n += k;
}
static char *build_list(srv *s, ftp_sess *fs, const char *arg, int names_only, size_t *outn) {
    srv_ftp_state *f = s->ftp; char *buf = malloc(1); size_t n = 0; buf[0] = 0;
    while (arg && *arg == '-') { while (*arg && *arg != ' ') arg++; while (*arg == ' ') arg++; }   /* skip -l -a */
    char dir[1024], pat[256] = "";
    if (!arg || !*arg) snprintf(dir, sizeof dir, "%s", fs->cwd);
    else if (strpbrk(arg, "*?")) {
        const char *sl = strrchr(arg, '/');
        if (sl) { char d0[1024]; snprintf(d0, sizeof d0, "%.*s", (int)(sl - arg), arg); resolve(fs->cwd, d0, dir, sizeof dir); snprintf(pat, sizeof pat, "%s", sl + 1); }
        else { snprintf(dir, sizeof dir, "%s", fs->cwd); snprintf(pat, sizeof pat, "%s", arg); }
    } else resolve(fs->cwd, arg, dir, sizeof dir);
    EnterCriticalSection(&s->cs);
    ftp_ent *one = !pat[0] ? find_ent(f, dir) : NULL;
    if (one && !one->dir) list_line(&buf, &n, one, names_only);
    else for (int i = 0; i < f->ne; i++) {
        char par[1024]; parent_of(f->e[i].path, par);
        if (strcmp(par, dir)) continue;
        const char *name = strrchr(f->e[i].path, '/') + 1;
        if (pat[0] && !wild(pat, name)) continue;
        list_line(&buf, &n, &f->e[i], names_only);
    }
    LeaveCriticalSection(&s->cs);
    *outn = n; return buf;
}

static int check_override(srv_conn *c, const char *line) {
    const srv_ftp_config *fc = c->s->cfg.ftp; srv_ftp_state *f = c->s->ftp;
    for (int i = 0; fc && i < fc->noverrides; i++) {
        const srv_ftp_override *o = &fc->overrides[i];
        if (_strnicmp(line, o->cmd_prefix, strlen(o->cmd_prefix))) continue;
        EnterCriticalSection(&c->s->cs);
        int ok = !o->times || f->ov_used[i] < o->times; if (ok) f->ov_used[i]++;
        LeaveCriticalSection(&c->s->cs);
        if (!ok) continue;
        reply(c, "%s", o->reply);
        return 1;
    }
    return 0;
}

void srv_ftp_conn(srv_conn *c) {
    srv *s = c->s; srv_ftp_state *f = s->ftp; const srv_ftp_config *fc = s->cfg.ftp;
    ftp_sess fs; memset(&fs, 0, sizeof fs); strcpy(fs.cwd, "/"); fs.pasv = INVALID_SOCKET; fs.type = 'A';
    if (reply(c, "%s", fc && fc->banner ? fc->banner : "220 i7 test FTP ready")) return;
    char line[2048];
    for (int ncmd = 0; ncmd < 2000 && !s->stop; ncmd++) {
        if (!read_line(c, line, sizeof line)) break;
        char rec[2048];
        if (!_strnicmp(line, "PASS", 4) && !(fc && fc->record_pass)) snprintf(rec, sizeof rec, "PASS ***"); else snprintf(rec, sizeof rec, "%s", line);
        srv_record(s, SRV_EV_FTP_CMD, c->id, -1, rec, strlen(rec));
        EnterCriticalSection(&s->cs);
        if (s->nftpcmd == s->capftpcmd) { s->capftpcmd = s->capftpcmd ? s->capftpcmd * 2 : 32; s->ftpcmd = realloc(s->ftpcmd, s->capftpcmd * sizeof *s->ftpcmd); }
        s->ftpcmd[s->nftpcmd++] = strdup(rec);
        LeaveCriticalSection(&s->cs);
        if (check_override(c, line)) continue;
        char cmd[16] = ""; const char *arg = line; int k = 0;
        while (*arg && *arg != ' ' && k < 15) cmd[k++] = (char)toupper((unsigned char)*arg++);
        cmd[k] = 0; while (*arg == ' ') arg++;
        char path[1024]; resolve(fs.cwd, arg, path, sizeof path);
        if (!strcmp(cmd, "USER")) reply(c, "331 Password required for %s.", arg);
        else if (!strcmp(cmd, "PASS")) reply(c, "230 User logged in.");
        else if (!strcmp(cmd, "SYST")) reply(c, "215 UNIX Type: L8");
        else if (!strcmp(cmd, "FEAT")) reply(c, "211-Features:\r\n SIZE\r\n MDTM\r\n REST STREAM\r\n EPSV\r\n211 End");
        else if (!strcmp(cmd, "OPTS") || !strcmp(cmd, "MODE") || !strcmp(cmd, "STRU")) reply(c, "200 OK.");
        else if (!strcmp(cmd, "NOOP")) reply(c, "200 NOOP ok.");
        else if (!strcmp(cmd, "ALLO")) reply(c, "202 ALLO not needed.");
        else if (!strcmp(cmd, "PWD") || !strcmp(cmd, "XPWD")) reply(c, "257 \"%s\" is current directory.", fs.cwd);
        else if (!strcmp(cmd, "CWD") || !strcmp(cmd, "XCWD") || !strcmp(cmd, "CDUP")) {
            if (!strcmp(cmd, "CDUP")) resolve(fs.cwd, "..", path, sizeof path);
            EnterCriticalSection(&s->cs); int d = is_dir(f, path); LeaveCriticalSection(&s->cs);
            if (d) { strcpy(fs.cwd, path); reply(c, "250 CWD command successful."); }
            else reply(c, "550 %s: No such file or directory.", arg);
        }
        else if (!strcmp(cmd, "TYPE")) { fs.type = (char)toupper((unsigned char)arg[0]); reply(c, "200 Type set to %c.", fs.type); }
        else if (!strcmp(cmd, "PASV")) {
            if (fs.pasv != INVALID_SOCKET) SWS.closesocket(fs.pasv);
            unsigned short p; fs.pasv = srv_listen_v4(&p);
            if (fs.pasv == INVALID_SOCKET) reply(c, "425 Cannot open passive connection.");
            else reply(c, "227 Entering Passive Mode (127,0,0,1,%u,%u).", p >> 8, p & 255);
        }
        else if (!strcmp(cmd, "EPSV")) {
            if (fs.pasv != INVALID_SOCKET) SWS.closesocket(fs.pasv);
            unsigned short p; fs.pasv = srv_listen_v4(&p);
            if (fs.pasv == INVALID_SOCKET) reply(c, "425 Cannot open passive connection.");
            else reply(c, "229 Entering Extended Passive Mode (|||%u|)", p);
        }
        else if (!strcmp(cmd, "PORT")) {
            unsigned h[6]; if (sscanf(arg, "%u,%u,%u,%u,%u,%u", &h[0], &h[1], &h[2], &h[3], &h[4], &h[5]) == 6 && h[0] == 127) {
                for (int i = 0; i < 4; i++) fs.port_addr[i] = (unsigned char)h[i];
                fs.port_af = AF_INET; fs.port_port = (unsigned short)(h[4] << 8 | h[5]); fs.have_port = 1;
                if (fs.pasv != INVALID_SOCKET) { SWS.closesocket(fs.pasv); fs.pasv = INVALID_SOCKET; }
                reply(c, "200 PORT command successful.");
            } else reply(c, "501 Illegal PORT command (loopback only).");
        }
        else if (!strcmp(cmd, "EPRT")) {
            char dlm = arg[0]; unsigned af = 0, port = 0; char addr[64] = "";
            char fmt[64]; snprintf(fmt, sizeof fmt, "%c%%u%c%%63[^%c]%c%%u%c", dlm, dlm, dlm, dlm, dlm);
            if (dlm && sscanf(arg, fmt, &af, addr, &port) == 3 && (af == 1 ? !strcmp(addr, "127.0.0.1") : !strcmp(addr, "::1"))) {
                memset(fs.port_addr, 0, 16);
                if (af == 1) { fs.port_af = AF_INET; fs.port_addr[0] = 127; fs.port_addr[3] = 1; } else { fs.port_af = AF_INET6; fs.port_addr[15] = 1; }
                fs.port_port = (unsigned short)port; fs.have_port = 1;
                reply(c, "200 EPRT command successful.");
            } else reply(c, "501 Illegal EPRT command (loopback only).");
        }
        else if (!strcmp(cmd, "LIST") || !strcmp(cmd, "NLST")) {
            size_t n; char *lst;
            if (!strcmp(cmd, "LIST") && fc && fc->list_override) { n = strlen(fc->list_override); lst = malloc(n + 1); memcpy(lst, fc->list_override, n + 1); }
            else lst = build_list(s, &fs, arg, !strcmp(cmd, "NLST"), &n);
            SOCKET d = open_data(c, &fs);
            if (d == INVALID_SOCKET) reply(c, "425 Can't open data connection.");
            else {
                reply(c, "150 Opening ASCII mode data connection for file list.");
                int r = data_send(d, lst, n); close_data(d);
                srv_recordf(s, SRV_EV_FTP_DATA, c->id, "%s %zu bytes", cmd, n);
                reply(c, r ? "426 Connection closed; transfer aborted." : "226 Transfer complete.");
            }
            free(lst);
        }
        else if (!strcmp(cmd, "RETR")) {
            EnterCriticalSection(&s->cs); ftp_ent *e = find_ent(f, path); char *data = NULL; long n = 0;
            if (e && !e->dir) { long off = fs.rest < e->n ? fs.rest : e->n; n = e->n - off; data = malloc(n + 1); memcpy(data, e->data + off, n); }
            LeaveCriticalSection(&s->cs);
            fs.rest = 0;
            if (!data) reply(c, "550 %s: No such file or directory.", arg);
            else {
                SOCKET d = open_data(c, &fs);
                if (d == INVALID_SOCKET) reply(c, "425 Can't open data connection.");
                else {
                    const char *nm = strrchr(path, '/') + 1;
                    reply(c, "150 Opening %s mode data connection for %s (%ld bytes).", fs.type == 'I' ? "BINARY" : "ASCII", nm, n);
                    int r = data_send(d, data, n); close_data(d);
                    srv_recordf(s, SRV_EV_FTP_DATA, c->id, "RETR %s %ld bytes", path, n);
                    reply(c, r ? "426 Connection closed; transfer aborted." : "226 Transfer complete.");
                }
                free(data);
            }
        }
        else if (!strcmp(cmd, "STOR") || !strcmp(cmd, "APPE")) {
            SOCKET d = open_data(c, &fs);
            if (d == INVALID_SOCKET) { reply(c, "425 Can't open data connection."); continue; }
            reply(c, "150 Opening %s mode data connection for %s.", fs.type == 'I' ? "BINARY" : "ASCII", arg);
            char *buf = NULL; size_t n = 0; int bad = 0;
            for (;;) {
                buf = realloc(buf, n + 65536 + 1);
                int r = SWS.recv(d, buf + n, 65536, 0);
                if (r == 0) break;
                if (r < 0 || n > (64u << 20)) { bad = 1; break; }
                n += r;
            }
            SWS.closesocket(d);
            EnterCriticalSection(&s->cs);
            ftp_ent *e = add_ent(f, path);
            if (!strcmp(cmd, "APPE") && e->data) { e->data = realloc(e->data, e->n + n + 1); memcpy(e->data + e->n, buf, n); e->n += n; }
            else { free(e->data); e->data = malloc(n + 1); memcpy(e->data, buf, n); e->n = (long)n; }
            e->data[e->n] = 0; e->dir = 0;
            LeaveCriticalSection(&s->cs);
            srv_recordf(s, SRV_EV_FTP_DATA, c->id, "%s %s %zu bytes", cmd, path, n);
            free(buf);
            reply(c, bad ? "426 Connection closed; transfer aborted." : "226 Transfer complete.");
        }
        else if (!strcmp(cmd, "SIZE") || !strcmp(cmd, "MDTM")) {
            EnterCriticalSection(&s->cs); ftp_ent *e = find_ent(f, path); long n = e && !e->dir ? e->n : -1; char m[16] = ""; if (e) strcpy(m, e->mdtm);
            LeaveCriticalSection(&s->cs);
            if (n < 0) reply(c, "550 %s: No such file.", arg);
            else if (!strcmp(cmd, "SIZE")) reply(c, "213 %ld", n);
            else reply(c, "213 %s", m);
        }
        else if (!strcmp(cmd, "DELE")) {
            EnterCriticalSection(&s->cs); ftp_ent *e = find_ent(f, path); int ok = e && !e->dir; if (ok) del_ent(f, e); LeaveCriticalSection(&s->cs);
            reply(c, ok ? "250 DELE command successful." : "550 %s: No such file.", arg);
        }
        else if (!strcmp(cmd, "MKD") || !strcmp(cmd, "XMKD")) {
            EnterCriticalSection(&s->cs); int exists = find_ent(f, path) != NULL || !strcmp(path, "/");
            if (!exists) add_ent(f, path)->dir = 1;
            LeaveCriticalSection(&s->cs);
            if (exists) reply(c, "550 %s: File exists.", arg); else reply(c, "257 \"%s\" directory created.", path);
        }
        else if (!strcmp(cmd, "RMD") || !strcmp(cmd, "XRMD")) {
            EnterCriticalSection(&s->cs); ftp_ent *e = find_ent(f, path); int ok = e && e->dir;
            for (int i = 0; ok && i < f->ne; i++) { char par[1024]; if (!strcmp(parent_of(f->e[i].path, par), path)) ok = 0; }
            if (ok) del_ent(f, e);
            LeaveCriticalSection(&s->cs);
            reply(c, ok ? "250 RMD command successful." : "550 %s: Cannot remove directory.", arg);
        }
        else if (!strcmp(cmd, "RNFR")) {
            EnterCriticalSection(&s->cs); int ok = find_ent(f, path) != NULL; LeaveCriticalSection(&s->cs);
            if (ok) { strcpy(fs.rnfr, path); reply(c, "350 File exists, ready for destination name."); }
            else { fs.rnfr[0] = 0; reply(c, "550 %s: No such file or directory.", arg); }
        }
        else if (!strcmp(cmd, "RNTO")) {
            if (!fs.rnfr[0]) { reply(c, "503 Bad sequence of commands."); continue; }
            EnterCriticalSection(&s->cs); ftp_ent *e = find_ent(f, fs.rnfr); int ok = e && !find_ent(f, path);
            if (ok) { free(e->path); e->path = strdup(path); }
            LeaveCriticalSection(&s->cs);
            fs.rnfr[0] = 0;
            reply(c, ok ? "250 Rename successful." : "550 Rename failed.");
        }
        else if (!strcmp(cmd, "REST")) { fs.rest = atol(arg); reply(c, "350 Restarting at %ld. Send STORE or RETRIEVE.", fs.rest); }
        else if (!strcmp(cmd, "ABOR")) reply(c, "226 ABOR command successful.");
        else if (!strcmp(cmd, "QUIT")) { reply(c, "221 Goodbye."); break; }
        else reply(c, "502 Command not implemented.");
    }
    if (fs.pasv != INVALID_SOCKET) SWS.closesocket(fs.pasv);
    srv_recordf(s, SRV_EV_SCRIPT_DONE, c->id, "ftp session end");
}
