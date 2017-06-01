#!/usr/bin/env python
import itertools
from string import ascii_lowercase
import requests
import json

pos = lambda t,s:t.index(s)+len(s)

def dump(obj):
	for attr in dir(obj):
		try:
			print "obj.%s = %s" % (attr, getattr(obj, attr))
		except:
			pass

def gen_things(repeat=1):
	"""
		Generate longer and longer lowercase strings
	"""
	for x in itertools.product(ascii_lowercase, repeat=repeat):
		yield x
	for x in gen_things(repeat+1):
		yield x

requests.packages.urllib3.disable_warnings()

def start_session():
	session = requests.session()		
	session.get(url,verify=False)
	return session

def post(**kwargs):
	login = session.post(url, data=kwargs, verify=False) #this should log in in, i don't have an account there to test.
	return login

def get(url_in):
	login = session.get(url_in, verify=False) #this should log in in, i don't have an account there to test.
	return login

