#!/usr/bin/env python3
# Generate secret tokens
# Author Yehia Elghaly

import random
import string
import os.path
import secrets

length = 8

print("secret token= ", (secrets.token_hex(16)[0:length]))
print("secret token= ", (secrets.token_hex(16)[0:length]))

def passwordGenerate(PasswordLength=8):
	password = string.ascii_letters + string.digits + string.punctuation
	return ''.join(secrets.choice(password) for i in rnage(PasswordLength))

passy = (passwordGenerate(8) )
passi = (passwordGenerate(10))
print(passy)
print(passi)
