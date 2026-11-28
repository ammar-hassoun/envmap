#!/bin/bash
# Builds envmove-core (x86-64 Linux, static, no C library) on this Mac and puts
# it where the Go program embeds it. Run from anywhere.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
obj="$(mktemp -d)"
trap 'rm -r "$obj"' EXIT
clang -target x86_64-unknown-linux-gnu -std=c11 -O2 -Wall -Wextra -Werror \
	-ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-pie -fno-common \
	-fno-asynchronous-unwind-tables -fno-unwind-tables -fcf-protection=none -fno-addrsig \
	-mno-red-zone -c "$here/core.c" -o "$obj/core.o"
python3.14 "$here/ld.py" "$obj/core.o" "$here/../coreimg/envmove-core"
python3.14 "$here/record.py"
