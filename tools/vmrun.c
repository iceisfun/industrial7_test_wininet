/* vmrun.c - guest-side runner for the Win10 VM (docs/VM_RUN.md, docs/research/04_server_and_vm_design.md section 2).
 *
 *   vmrun.exe [-t SECONDS] [-o OUT] [-n NAME] -- EXE [ARGS...]
 *
 * Runs EXE in a kill-on-close job object with stdout+stderr on a pipe, and forwards everything to OUT
 * (default \\.\COM1, opened ONCE by this process) framed as
 *     @@I7 BEGIN <name> <exe>
 *     ...child output verbatim...
 *     @@I7 END <name> exit=<code> ms=<elapsed> timeout=<0|1> bytes=<n>
 * On timeout the whole job (child + grandchildren) is terminated and exit=0xDEAD0001.
 * Exit code: the child's (or 0xDEAD0001 / 0xDEAD0000 spawn failure).
 * Several runs in a row from run.cmd are fine: COM1 is exclusive, so nothing else may write it while vmrun runs. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static HANDLE g_out; static volatile LONG g_bytes;
static void out_write(const void *b, DWORD n) { DWORD w; while (n) { if (!WriteFile(g_out, b, n, &w, NULL) || !w) return; b = (const char *)b + w; n -= w; } }
static void out_printf(const char *fmt, ...) { char t[1024]; va_list a; va_start(a, fmt); int n = vsnprintf(t, sizeof t, fmt, a); va_end(a); if (n > 0) out_write(t, n < (int)sizeof t ? n : (int)sizeof t - 1); }

static DWORD WINAPI pump(LPVOID p) {
    HANDLE r = p; char buf[16384]; DWORD n;
    while (ReadFile(r, buf, sizeof buf, &n, NULL) && n) { out_write(buf, n); InterlockedAdd(&g_bytes, n); }
    return 0;
}

int main(int argc, char **argv) {
    DWORD secs = 600; const char *out = "\\\\.\\COM1", *name = NULL; int i = 1;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "-t") && i + 1 < argc) secs = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[++i];
        else if (!strcmp(argv[i], "-n") && i + 1 < argc) name = argv[++i];
        else if (!strcmp(argv[i], "--")) { i++; break; }
        else break;
    }
    if (i >= argc) { fprintf(stderr, "usage: vmrun [-t s] [-o out] [-n name] -- exe args\n"); return 2; }
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX); /* inherited by the child */

    g_out = CreateFileA(out, GENERIC_WRITE, FILE_SHARE_READ, NULL, strncmp(out, "\\\\.\\", 4) ? CREATE_ALWAYS : OPEN_EXISTING, 0, NULL);
    if (g_out == INVALID_HANDLE_VALUE) { fprintf(stderr, "vmrun: open %s err=%lu\n", out, GetLastError()); return 3; }
    if (!strncmp(out, "\\\\.\\COM", 7)) {
        DCB d = { sizeof d }; GetCommState(g_out, &d); d.BaudRate = CBR_115200; d.ByteSize = 8; d.Parity = NOPARITY; d.StopBits = ONESTOPBIT;
        d.fOutxCtsFlow = d.fOutxDsrFlow = FALSE; d.fDtrControl = DTR_CONTROL_ENABLE; d.fRtsControl = RTS_CONTROL_ENABLE; SetCommState(g_out, &d);
        COMMTIMEOUTS to = {0}; to.WriteTotalTimeoutConstant = 30000; SetCommTimeouts(g_out, &to);
    }

    /* command line: quoted exe + the remaining args verbatim */
    char cmd[8192]; int o = snprintf(cmd, sizeof cmd, "\"%s\"", argv[i]);
    for (int k = i + 1; k < argc && o < (int)sizeof cmd - 4; k++) o += snprintf(cmd + o, sizeof cmd - o, strchr(argv[k], ' ') ? " \"%s\"" : " %s", argv[k]);
    if (!name) { name = strrchr(argv[i], '\\'); name = name ? name + 1 : argv[i]; }

    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE }; HANDLE rd, wr;
    CreatePipe(&rd, &wr, &sa, 1 << 16); SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    HANDLE nul = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    HANDLE job = CreateJobObjectA(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION li; memset(&li, 0, sizeof li);
    li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &li, sizeof li);

    STARTUPINFOA si; PROCESS_INFORMATION pi; memset(&si, 0, sizeof si); si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES; si.hStdInput = nul; si.hStdOutput = wr; si.hStdError = wr;
    out_printf("@@I7 BEGIN %s %s\r\n", name, cmd);
    LARGE_INTEGER f, t0, t1; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&t0);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        out_printf("@@I7 END %s exit=0xDEAD0000 ms=0 timeout=0 bytes=0 spawn_err=%lu\r\n", name, GetLastError());
        return (int)0xDEAD0000;
    }
    AssignProcessToJobObject(job, pi.hProcess); ResumeThread(pi.hThread); CloseHandle(pi.hThread);
    CloseHandle(wr); CloseHandle(nul);
    HANDLE th = CreateThread(NULL, 0, pump, rd, 0, NULL);
    DWORD code = 0, timed_out = 0;
    if (WaitForSingleObject(pi.hProcess, secs * 1000) != WAIT_OBJECT_0) { timed_out = 1; TerminateJobObject(job, 0xDEAD0001); WaitForSingleObject(pi.hProcess, 5000); }
    GetExitCodeProcess(pi.hProcess, &code);
    /* grandchildren may still hold the pipe: kill the job, then give the pump a bounded drain */
    TerminateJobObject(job, code);
    if (WaitForSingleObject(th, 5000) != WAIT_OBJECT_0) { CancelSynchronousIo(th); WaitForSingleObject(th, 2000); }
    QueryPerformanceCounter(&t1);
    out_printf("\r\n@@I7 END %s exit=0x%lx ms=%lld timeout=%lu bytes=%ld\r\n", name, code, (t1.QuadPart - t0.QuadPart) * 1000 / f.QuadPart, timed_out, g_bytes);
    FlushFileBuffers(g_out); CloseHandle(g_out); CloseHandle(pi.hProcess); CloseHandle(job);
    return timed_out ? (int)0xDEAD0001 : (int)code;
}
