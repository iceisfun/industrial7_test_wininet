# Each directory under tests/ builds to build/<dir>.exe (all .c in it + every common/*.c).
# The DLL under test is deliberately NOT linked; everything resolves via GetProcAddress.
# common/srv_*.c (loopback servers) also resolve ws2_32/sspi/crypt32/ncrypt at run time: no -lws2_32 etc.
CC      = x86_64-w64-mingw32-gcc
CFLAGS  ?= -O1 -Wall -Wno-unused-function -Wno-unused-variable -Wno-unused-but-set-variable -Wno-format -Wno-misleading-indentation
AREAS   := $(notdir $(wildcard tests/*))
EXES    := $(addprefix build/,$(addsuffix .exe,$(AREAS)))
COMMON_C := $(wildcard common/*.c)
COMMON_H := $(wildcard common/*.h)
all: $(EXES) build/tools/vmrun.exe
.SECONDEXPANSION:
build/%.exe: $$(wildcard tests/$$*/*.c) $(COMMON_C) $(COMMON_H)
	@mkdir -p build
	$(CC) $(CFLAGS) -Icommon -o $@ $(wildcard tests/$*/*.c) $(COMMON_C) -static -lkernel32 -ladvapi32 -lntdll
# Guest-side runner for the Win10 VM (tools/vm_run.sh); kept out of build/*.exe so run_all.bat does not pick it up.
build/tools/vmrun.exe: tools/vmrun.c
	@mkdir -p build/tools
	$(CC) -O1 -Wall -o $@ $< -static
clean: ; rm -rf build
# Validation under Wine in a headless sandbox (see tools/wine_run.sh). Windows is the authority.
wine-run: all
	@for e in $(EXES); do echo "== $$e"; tools/wine_run.sh $$e | grep -E '^(FAIL|SKIP|SUMMARY)|^  (FAIL|NOTE)'; done
# Real Windows 10 VM (tools/vm_run.sh, docs/VM_RUN.md)
vm: all
	tools/vm_run.sh --all
.PHONY: all clean wine-run vm
