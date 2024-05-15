#!/usr/bin/env python3
# Send Post Request
# Author Yehia Elghaly

import requests
from bs4 import BeautifulSoup

site = "http://192.168.0.102/dvwa/login.php"

def get_token(source):
    soup = BeautifulSoup(source, "html.parser")
    return soup.find('input', { "type" : "hidden" })['value']

with requests.Session() as s:
    source = s.get(site).text
    login = {
        "username"   : "admin",
        "password"   : "password",
        "Login"      : "Submit",
        "user_token" : get_token(source)
    }
    r = s.post(site, data = login)
    print (r.text)