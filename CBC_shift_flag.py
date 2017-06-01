#!/usr/bin/python
#
# pwnable.kr solution for crypto1
# by pastebin
#
# this is actually quite similar to a past challenge I had done
# you shift the cipher along and bruteforce the first character of
# the cookie

import base64
from pwn import *
from functools import partial
from multiprocessing import Pool
import time
import hashlib
# find the length of the block

context.log_level = 30

def chunks(l, n):
	"""return a list of successive n-sized chunks from l."""
	arr = []
	for i in range(0, len(l), n):
		arr.append(l[i:i+n])
	return arr


def send_msg(msg):
	return get_enc("",msg)

def get_enc(myID, password):
	conn = remote("pwnable.kr", 9006)
	conn.recvuntil("Input your ID")
	conn.sendline(myID)
	conn.recvuntil("Input your PW")
	conn.sendline(password)
	conn.recvuntil("(")
	enc = conn.recvuntil(")")[:-1]
	return enc



def get_encoding(msg, block_num=0):

	response = send_msg(msg)

	blocks = chunks(response,16*2) # 16 block size, *2 because hex representation

	my_block = blocks[block_num]
	return my_block

def return_encoding_with_msg(msg, block_num=0):
	# print 'getting encoding'
	try:
		enc = get_encoding(msg, block_num)
		# print 'got encoding! I\'m ' + msg[-1]
		return enc , msg
	except:
		print ':( having a nap and trying again'
		time.sleep(1)
		return return_encoding_with_msg(msg, block_num)


def get_next_letter(banana):
	"""
	Give this function a string of 13 chars
	and it'll bruteforce to find the next char in 
	the flag
	"""
	
	nulls = 'a'*(15 - (len(banana)+2)%16)
	# 13 if we just started i.e we want to bruteforce the first character
	# 14 if we've got 1 so we want to 
	# "Need to get this block  goal_block

	# once we get the first block
	# we'll need to look at the next block over
	# so go back to sending 13 nulls
	# so that the 2nd to 16th characters are in the next block
	extra = int((len(banana)+2)/16)
	goal_block = get_encoding(nulls, block_num=(extra))
	attempts = []
	print "extra " + str(extra)
	print "this is the goal block"
	print goal_block
	for x in "1234567890abcdefghijklmnopqrstuvwxyz-_":
		block = nulls + "-" + banana + x
		# e = get_encoding(block, 2+extra)
		# if e == goal_block:
		#  return chr(x)
		attempts.append(block)


	print attempts
	pool = Pool(processes=38) 
	res = pool.map(partial(return_encoding_with_msg, block_num=(extra)), attempts)
	pool.close()                         
	pool.join() 
	for r, msg in res:
		# print r
		# print r + msg[-1]
		if r == goal_block:
			print 'Success!'
			print msg
			return msg[-1]

	return '?'


cookie = list("you_will_never_guess_this_sugar_honey_salt_cookie")
while True:
	# get the next letter
	nl = get_next_letter(''.join(cookie))
	if nl != '?':
		cookie.append(nl)
		print ''.join(cookie)

	else:
		break

cookie = ''.join(cookie)
print "[!] The cookie is " + cookie
user = "admin"


pw = hashlib.sha256(user+cookie).hexdigest()
print pw

conn = remote("pwnable.kr", 9006)
conn.recvuntil("Input your ID")
conn.sendline(user)
conn.recvuntil("Input your PW")
conn.sendline(pw)
conn.interactive()

# byte to byte leaking against block cipher plaintext is fun!!
