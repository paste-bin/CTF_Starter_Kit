#!/usr/bin/python

# exploit server 01

# client: what is in the fridge
# server: (depickles local object) this is in the fridge
# client: makes note (arbitrary file write)

import sys
import socket
import base64
import select
from pwn import *
from time import sleep

BLOCK_SIZE = 16

# REDACTED 

token = conn.recvuntil("\n").rstrip()

offset = flag_len + k + len(":Admin_token=") - BLOCK_SIZE

hak_str = [x for x in base64.b64decode(token)]

hak_str[offset] = chr(ord(hak_str[offset]) ^ ord('0') ^ ord('1'))

# haks = chunks(''.join(hak_str), BLOCK_SIZE)
haks = base64.b64encode(''.join(hak_str))

conn.sendline(haks)
# off by one vulnrability means you can get the flag by 
# just sending the command '6' and no auth is checked
my_input = "7" 
conn.sendline(my_input + "\n")

print conn.recvuntil('\n')
print conn.recvuntil('\n')


