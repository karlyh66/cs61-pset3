DEP_CC:=cc  -I.  -m64 -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -mno-sse3 -mno-3dnow -ffreestanding -fno-omit-frame-pointer -fno-pic -Wall -W -Wshadow -Wno-format -Wno-unused-parameter -Wstack-usage=1024 -fno-stack-protector -std=gnu11 -gdwarf -MD -MF .deps/.d -MP  _  -Os --gc-sections -z max-page-size=0x1000 -static -nostdlib -nostartfiles -m elf_x86_64
DEP_PREFER_GCC:=
