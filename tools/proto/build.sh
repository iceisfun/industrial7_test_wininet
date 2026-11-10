#!/usr/bin/env bash
# Build the VM prototypes into tools/proto/out/ (not committed) and assemble a payload dir for win10_run.sh.
#   build.sh [run.cmd|run2.cmd]   which probe script becomes the payload run.cmd
set -eu
cd "$(dirname "$0")"; mkdir -p out
CC=x86_64-w64-mingw32-gcc
$CC -O1 -Wall -Wno-unused -o out/proto.exe proto.c -static -lwininet -lwinhttp -lws2_32 -lcrypt32 -lsecur32 -lncrypt -lversion -ladvapi32
$CC -O1 -Wall -o out/vmrun.exe vmrun.c -static
cp "${1:-run.cmd}" out/run.cmd
echo "payload: $(pwd)/out"
