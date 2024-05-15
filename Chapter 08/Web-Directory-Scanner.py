#!/usr/bin/env python3
# Web Directory Scanner
# Author Yehia Elghaly

import requests
from fake_useragent import UserAgent
from colorama import Fore, Back, Style

def web_scanner():
    url = UserAgent()
    user_agent = url.random
    web='http://192.168.0.102/DVWA/'
    fileloc = 'wordlist.txt'
    with open(fileloc) as fp:
        line = fp.readline()
        while line:
            combined = web+line.strip()
            r = requests.get(combined, headers={'User-Agent': user_agent})
            if r.status_code == 200:
                print (Fore.CYAN + "")
                print (line.strip(),'\n',r, Fore.CYAN + "BINGO")
            line = fp.readline()
            if r.status_code == 404:
                print (Fore.CYAN + "")
                print (line.strip(),'\n',r, Fore.RED + "Not Found")
            line = fp.readline()

print (web_scanner())