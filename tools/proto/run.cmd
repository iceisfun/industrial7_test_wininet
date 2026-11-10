@echo off
rem Payload for ~/w10lab/tools/win10_run.sh: probes for docs/research/04_server_and_vm_design.md.
rem COM1 is exclusive: only one writer at a time (each line below opens and closes it).
cd /d %~dp0
echo @@T boot_hook %date% %time% > COM1
netsh advfirewall show allprofiles state > COM1
sc query WinDefend > COM1
sc query WinHttpAutoProxySvc > COM1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" > COM1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" > COM1 2>&1
ipconfig /all > COM1
echo @@T probes_start %time% > COM1
vmrun.exe -t 400 -n proto -- proto.exe
echo @@T probes_end %time% > COM1
rem serial throughput: cmd redirection (unbuffered, buffered) vs the exe opening COM1 itself vs vmrun pipe
echo @@T ser0 %time% > COM1
proto.exe --spew 131072 > COM1
echo @@T ser1 %time% > COM1
proto.exe --spew 131072 b > COM1
echo @@T ser2 %time% > COM1
proto.exe --com1 131072
echo @@T ser3 %time% > COM1
vmrun.exe -t 60 -n spew_vmrun -- proto.exe --spew 131072
echo @@T ser4 %time% > COM1
rem runner kill/crash handling
vmrun.exe -t 5 -n hang -- proto.exe --hang
echo @@T hang_rc %errorlevel% > COM1
vmrun.exe -t 30 -n crash -- proto.exe --crash
echo @@T crash_rc %errorlevel% > COM1
rem COM1 contention: a second writer while vmrun holds COM1
vmrun.exe -t 10 -n contend -- cmd /c "echo inner > COM1 & echo inner_rc=%%errorlevel%%"
echo @@T done %time% > COM1
exit /b 0
