#!/bin/sh
x86_64-w64-mingw32-gcc \
  -shared -lpsapi \
  -O2 \
  -Wall \
  -Wl,--enable-stdcall-fixup \
  dll.c \
  -o ../../../version.dll

