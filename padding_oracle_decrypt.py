#!/usr/bin/python

# exploit server 01

# client: what is in the fridge
# server: (depickles local object) this is in the fridge
# client: makes note (arbitrary file write)

import os
import sys
import socket
import base64
import select
from pwn import *
from time import sleep
from Crypto.Cipher import AES


# the block size for the cipher object; must be 16 per FIPS-197
BLOCK_SIZE = 16

# wrap everything in try cathes 
# make it load flags

# the block size for the cipher object; must be 16 per FIPS-197
BLOCK_SIZE = 16


# pad with the number of bytes needed to pad as the value PKSC7 or whatevs
# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: c.encrypt(s)
DecodeAES = lambda c, e: c.decrypt(e)

# xor 2 lists
xor = lambda s, t: [chr(ord(a) ^ ord(b)) for a, b in zip(s, t)]

secret = pad(flag1)

# this is for testing
# create a cipher object using the random secret
cipher = AES.new(secret)

def chunks(l, n):
	"""return a list of successive n-sized chunks from l."""
	arr = []
	for i in range(0, len(l), n):
		arr.append(l[i:i+n])
	return arr

def encode(string):
	"""
		encode a string
	"""
	encoded = EncodeAES(cipher, string)
	return encoded

def decode(string):
	"""
		decode the encoded string
	"""
	decoded = DecodeAES(cipher, string)
	return decoded

def cbc_encrypt(string):
	blocks = string
	cipher_blocks = [encode(blocks[0])]
	for prevIndex, block in enumerate(blocks[1:]):
		# do the xor
		pre_encode = xor(cipher_blocks[prevIndex], block)
		cipher_string = [x for x in encode(''.join(pre_encode))]
		# print [x for x in pre_encode2]
		cipher_blocks.append(cipher_string)
	return cipher_blocks

def cbc_decrypt(string):
	cipher_blocks = string
	blocks = [decode(''.join(cipher_blocks[0]))]
	for prevIndex, cipher_string in enumerate(cipher_blocks[1:]):
		pre_encode = [x for x in decode(''.join(cipher_string))]
		# do the xor
		block = xor(pre_encode, cipher_blocks[prevIndex])
		blocks.append(block)

	return blocks

def validate(conn, blocks):
	haks = base64.b64encode(''.join([ ''.join(a) for a in blocks]))


	blocks = chunks(base64.b64decode(haks), BLOCK_SIZE)

	# plainText = ''.join([ ''.join(a) for a in cbc_decrypt(blocks)])
	# counter = ord(plainText[-1])
	# print [x for x in plainText]


	# if counter < 0 or counter > 16:
	# 	return False

	# for p in plainText[-counter:]:
	# 	if ord(p) != counter:
	# 		return False
	# return True


	haks = base64.b64encode(''.join([ ''.join(a) for a in blocks]))
	conn.sendline(haks)
	resp = conn.recvuntil("\n", timeout=0.2)
	while "valid" not in resp:
		conn.sendline(haks)
		resp = conn.recvuntil("\n", timeout=0.2)
		# conn.recvuntil('\n')

	# print resp
	if "invalid" in resp:
		return False
	else:
		# # conn.interactive()
		# conn.recv()
		# print conn.recv()
		# # conn.sendline('2')
		# # conn.recvuntil("Audio\n")
		# print 'hi'
		return True


# REDACTED

# this is the legit one 
cipher_blocks = chunks(base64.b64decode(token), BLOCK_SIZE)

# space to put stuff as I crack it
plain_blocks = [['?']*BLOCK_SIZE for x in range(len(cipher_blocks))]

# get the second block from the cipher
# we'll mess with the first fake block until we 
# get valid padding, then we know a valid decryption
# C' XOR 0x01  = Cn-1 XOR P

chars = [ord(x) for x in "aeiouAEIOUBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz1234567890!@#$%^&*()_+-={}[]\|;:'\",<.>/?"]
for x in range(0, 0xff + 1):
	if x not in chars:
		chars += [x]
print chars
with log.progress('Padding oracling:') as p:

	def crack_n(plain_blocks, n, block):
		fake_cipher = [['?']*BLOCK_SIZE, ['?']*BLOCK_SIZE]

		fake_cipher[1] = cipher_blocks[block]
		# C' XOR 0x0n = Cn-1 XOR P

		# sort out the last part of the fake cipher so 
		# that is generates the correct padding e.g 444
		# so that we can bruteforce on the next one X444
		# to make it encode to 4
		for i in range(1,n):
			fake_cipher[0][-i] = chr(ord(plain_blocks[block][-i]) ^ n ^ ord(cipher_blocks[block - 1][-i]))

		# bruteforce to find the cipher byte e.g find
		# the cipher byte that encodes to 
		# 4 so that it ends in 4444 (last 3 are obtained by induction)
		for x in chars:
			fake_cipher[0][-n] = chr(x)
			plain_blocks[block][-n] = chr(x ^ n ^ ord(cipher_blocks[block - 1][-n]))
			p.status(''.join([''.join(a) for a in plain_blocks]))
			if validate(conn, fake_cipher):
				return chr(x ^ n ^ ord(cipher_blocks[block - 1][-n]))
		return '?'


	for block in range(1,len(cipher_blocks)):
		for i in range(1,17):
			plain_blocks[block][-i] = crack_n(plain_blocks, i, block)

print ''.join([''.join(a) for a in plain_blocks])







