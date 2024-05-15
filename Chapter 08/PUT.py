#!/usr/bin/env python3
# Send PUT Request
#Author Yehia Elghaly

import requests 
  
# Making a PUT request 
method = requests.put('http://192.168.0.102/mutillidae/') 

print(method) 

print(method.content) 