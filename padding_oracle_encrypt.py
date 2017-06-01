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



# the block size for the cipher object; must be 16 per FIPS-197
BLOCK_SIZE = 16

import os
import sys
import code
import base64



# the block size for the cipher object; must be 16 per FIPS-197
BLOCK_SIZE = 16
# pad with the number of bytes needed to pad as the value PKSC7 or whatevs
# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

def chunks(l, n):
	"""return a list of successive n-sized chunks from l."""
	arr = []
	for i in range(0, len(l), n):
		arr.append(l[i:i+n])
	return arr

# redo this so that if anything isn't 100% ok, we just kill the connection and try again

def validate(conn, blocks):
	haks = base64.b64encode(''.join([ ''.join(a) for a in blocks]))
	conn.sendline(haks)
	resp = conn.recvuntil("\n", timeout=0.2)
	while "valid" not in resp:
		conn.sendline(haks)
		resp = conn.recvuntil("\n", timeout=0.2)
		# conn.recvuntil('\n')


	if "invalid" in resp:
		return False
	else:
		# conn.sendline('2')
		# conn.recvuntil("Audio is set to ON\n")
		return True


# Redacted

# this is the legit one 
cipher_blocks = chunks(base64.b64decode(token), BLOCK_SIZE)

# space to put stuff as I crack it
plain_blocks = [[chr(0x00)]*BLOCK_SIZE for x in range(len(cipher_blocks))]

# get the second block from the cipher
# we'll mess with the first fake block until we 
# get valid padding, then we know a valid decryption
# C' XOR 0x01  = Cn-1 XOR P

plaintext = pad("1234567890123456asdfasdfasdf:Give flag pls:Admin=1")

# this is the legit one 
plain_blocks = chunks(plaintext, BLOCK_SIZE)
# print plain_blocks
# space to put stuff as I crack it
my_cipher_blocks = [['C']*BLOCK_SIZE for x in range(len(plain_blocks))]

# get the second block from the cipher
# we'll mess with the first fake block until we 
# get valid padding, then we know a valid decryption
# C' XOR 0x01  = Cn-1 XOR P

# skip means skip the first solution, this is known to be false
def crack_n(plain_blocks, n, block, skip=False):
	fake_cipher = [[chr(0x00)]*BLOCK_SIZE, [chr(0x00)]*BLOCK_SIZE]
	fake_cipher[1] = my_cipher_blocks[block]
	# C' XOR 0x0n = Cn-1 XOR P

	# sort out the last part of the fake cipher so 
	# that is generates the correct padding e.g 444
	# so that we can bruteforce on the next one X444
	# to make it encode to 4
	for i in range(1,n):
		fake_cipher[0][-i] = chr(ord(plain_blocks[block][-i]) ^ n ^ ord(my_cipher_blocks[block - 1][-i]))

	# bruteforce to find the cipher byte e.g find
	# the cipher byte that encodes to 
	# 4 so that it ends in 4444 (last 3 are obtained by induction)
	for x in range(0, 0xff + 1):
		fake_cipher[0][-n] = chr(x)
		if validate(conn,  fake_cipher):
			# print plain_blocks[block]
			# print plain_blocks[block][-n]
			return (True, chr(x ^ n ^ ord(plain_blocks[block][-n])))

	print "Nope everything is fucked"
	return (False, '?')


with log.progress('Padding oracling:') as p:
	for block in range(len(plain_blocks)-1, 0, -1):
		for i in range(1,17):
			(worked, val) = crack_n(plain_blocks, i, block)
			if worked:
				my_cipher_blocks[block-1][-i] = val
				p.status(''.join([''.join(a) for a in my_cipher_blocks]))
			else:
				print 'NOT GUNNA WORK, change starting blocks'
				exit(1)


special_token = base64.b64encode(''.join([ ''.join(a) for a in my_cipher_blocks]))
conn.sendline(special_token)
conn.recvuntil('\n')
print "flag: " + conn.recvuntil('\n')
# print conn.recvuntil('\n')






