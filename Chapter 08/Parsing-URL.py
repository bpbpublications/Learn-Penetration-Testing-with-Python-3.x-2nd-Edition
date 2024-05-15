#!/usr/bin/env python3
# Parsing URL's from Websites
# Author Yehia Elghaly

from bs4 import BeautifulSoup
import requests
 
target = input("Enter Target URL: ")
page = requests.get(target)
info = page.text
 
soup = BeautifulSoup(info, 'lxml')
tags = soup.find_all('a')
 
for tag in tags:
    print(tag.get('href'))