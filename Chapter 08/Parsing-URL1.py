#!/usr/bin/env python3
# Parsing URL's from Websites
# Author Yehia Elghaly

import requests
from bs4 import BeautifulSoup

headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '2600',
    'User-Agent': 'Mozilla/5.0 (X11; Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/52.0'
    }
...
target = input("Enter Target URL: ")
reques = requests.get(target, headers)
soup = BeautifulSoup(reques.content, 'html.parser')
print(soup.prettify())