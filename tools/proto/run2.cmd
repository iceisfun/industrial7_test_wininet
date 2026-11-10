@echo off
rem Round 2 payload: dual-stack/refused-connect timing, certificate decision cache, request vs session flags,
rem FTP over loopback (PASV), large-output throughput through vmrun.
cd /d %~dp0
echo @@T r2_start %time% > COM1
vmrun.exe -t 300 -n r2 -- proto.exe --r2
echo @@T big0 %time% > COM1
vmrun.exe -t 120 -n big -- proto.exe --spew 2097152
echo @@T big1 %time% > COM1
exit /b 0
