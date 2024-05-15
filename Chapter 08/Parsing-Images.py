#!/usr/bin/env python3
# Parsing Images from Websites
#Author Yehia Elghaly

from urllib.request import urlopen
from bs4 import BeautifulSoup
import re

target = input ('Enter Target WebSite: ')
page = urlopen(target)
bs = BeautifulSoup(page, 'html.parser')
photos = bs.find_all('img', {'src':re.compile('.jpg')})
for photo in photos:
    print(photo['src']+'\n')

num1 = input("Enter image Link: ")
num2 = input ("Enter image name: ")
urllib.request.urlretrieve(num1, num2)