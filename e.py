from pwn import *
import sys

e = ELF("__ELFPATH",checksec=False)
libc = ELF("__LIBCPATH",checksec=False)
ld = ELF("__LDPATH",checksec=False)

nc = "nc __HOST __PORT"
HOST = nc.split(" ")[1]
PORT = int(nc.split(" ")[2])

dbg = 1
g_script = """
    set max-visualize-chunk-size 0x300
"""

context.binary = e
if len(sys.argv) > 1:
    io = remote(host=HOST,port=PORT)
else:
    io = e.process()
    if dbg:
        gdb.attach(io,g_script)

s   = lambda b: io.send(b)
sa  = lambda a,b: io.sendafter(a,b)
sl  = lambda b: io.sendline(b)
sla = lambda a,b: io.sendlineafter(a,b)
r   = lambda : io.recv()
ru  = lambda b:io.recvuntil(b)
rl  = lambda : io.recvline()
pu32= lambda b : u32(b.ljust(4,b"\0"))
pu64= lambda b : u64(b.ljust(8,b"\0"))
hlog= lambda i : print(f"[*]{hex(i)}")
shell = lambda : io.interactive()
payload = b""
def pay64(adr:int):global payload;payload = p64(adr)
def add64(adr:int):global payload;payload+= p64(adr)
def paybyte(data:bytes):global payload;payload = data
def addbyte(data:bytes):global payload;payload+= data

