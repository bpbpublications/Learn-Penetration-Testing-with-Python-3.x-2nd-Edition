#!/usr/bin/env python3
# Scrapy Spider
# Author Yehia Elghaly

import scrapy

class webspider(scrapy.Spider):
	name = 'Hacker'
	start_urls = ['https://www.hackerone.com/']

	def parse(self, response):
		pass