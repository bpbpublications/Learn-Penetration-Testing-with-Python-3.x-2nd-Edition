#!/usr/bin/env python3
# Parsing Cookies
#Author Yehia Elghaly

import requests

url = input("Enter Target Site: ")

response = requests.get(url)

response.cookies

for cookie in response.cookies:
	print('cookie domain = ' + cookie.domain)
	print('cookie name = ' + cookie.name)
	print('cookie value = ' + cookie.value)
	print('====================================')