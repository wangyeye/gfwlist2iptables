#!/usr/bin/env python
#coding=utf-8
#
# Generate a list of dnsmasq rules with ipset for gfwlist
#
# Copyright (C) 2014 http://www.shuyz.com
# Ref https://code.google.com/p/autoproxy-gfwlist/wiki/Rules

import urllib2
import re
import os
import datetime
import base64
import shutil
import ssl
import subprocess
import json
from IPy import IPSet, IP

mydnsip = '127.0.0.1'
mydnsport = '5353'
# Extra Domain;
EX_DOMAIN=[ \
'.google.com', \
'.google.com.hk', \
'.google.com.tw', \
'.google.com.sg', \
'.google.co.jp', \
'.google.co.kr', \
'.blogspot.com', \
'.blogspot.sg', \
'.blogspot.hk', \
'.blogspot.jp', \
'.blogspot.kr', \
'.gvt1.com', \
'.gvt2.com', \
'.gvt3.com', \
'.1e100.net', \
'.blogspot.tw' \
]

# the url of gfwlist
baseurl = 'https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt'
# match comments/title/whitelist/ip address
comment_pattern = '^\!|\[|^@@|^\d+\.\d+\.\d+\.\d+'
domain_pattern = '([\w\-\_]+\.[\w\.\-\_]+)[\/\*]*'
ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
tmpfile = '/tmp/gfwlisttmp'
# do not write to router internal flash directly
outfile = '/tmp/dnsmasq_list.conf'
rulesfile = './dnsmasq_list.conf'

fs =  file(outfile, 'w')
fs.write('# gfw list ipset rules for dnsmasq\n')
fs.write('# updated on ' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '\n')
fs.write('#\n')

print 'fetching list...'
if hasattr(ssl, '_create_unverified_context'):
	ssl._create_default_https_context = ssl._create_unverified_context
content = urllib2.urlopen(baseurl, timeout=15).read().decode('base64')

# write the decoded content to file then read line by line
tfs = open(tmpfile, 'w')
tfs.write(content)
tfs.close()
tfs = open(tmpfile, 'r')

print 'page content fetched, analysis...'

# remember all blocked domains, in case of duplicate records
domainlist = []
iptables = []
ret = IPSet()


for line in tfs.readlines():
	if re.findall(comment_pattern, line):
		print 'this is a comment line: ' + line
		#fs.write('#' + line)
	else:
		domain = re.findall(domain_pattern, line)
		if domain:
			try:
				found = domainlist.index(domain[0])
				print domain[0] + ' exists.'
			except ValueError:
				if ip_pattern.match(domain[0]):
					print 'skipping ip: ' + domain[0]
					continue
				print 'saving ' + domain[0]
				domainlist.append(domain[0])
				bashCommand = 'dig %s'%(domain[0])
				process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
				output, error = process.communicate()
				result = output.split('\n')
				for line in result:
					if line.startswith(domain[0]):
						reip = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
						for ip in reip.findall(line):
							url = 'https://wq.apnic.net/whois-search/query?searchtext=%s'%(ip)
							apnic = urllib2.urlopen(url, timeout=15).read()
							tab = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])/\d+').findall(apnic)
							iptables.extend(tab)
							iptables2 = sorted(list(set(iptables)))
							for ip2 in tab:
								ret.add(IP(ip2, make_net = True))
							print iptables2
				fs.write('server=/.%s/%s#%s\n'%(domain[0],mydnsip,mydnsport))
		else:
			print 'no valid domain in this line: ' + line

tfs.close()

for each in EX_DOMAIN:
	fs.write('server=/%s/%s#%s\n'%(each,mydnsip,mydnsport))

iptables2 = sorted(list(set(iptables)))
for each in iptables2:
	fs.write('%s\n'%(each))
for item in ret:
	fs.write('%s\n'%(item))

print 'write extra domain done'

fs.close();
print 'moving generated file to dnsmasg directory'
shutil.move(outfile, rulesfile)

print 'done!'
