#!/usr/bin/env python

import socket, argparse
from subprocess import Popen, PIPE
from os import getuid, mkdir, path

parser = argparse.ArgumentParser(prog='recon', usage='./recon.py [options]')
parser.add_argument('-u', "--url", type=str, 
	help='nslookup, quick dns brute and whois info on url')
parser.add_argument('-s', "--servicescan", type=str, 
	help='scan ip/range for services')
parser.add_argument('-l', "--livehosts", type=str, 
	help='pingscan ip/range for live hosts')
parser.add_argument('-p', "--ports", type=str, 
	help='port range for service scan')
parser.add_argument('-t', "--searchsploit", action="store_true", 
	help='use searchsploit')
args = parser.parse_args()

def fscan(ip):
	final = ''
	print ' [0o] Starting service scan of ' + ip
	cmd = 'nmap -sV -O %s -oX results/%s.xml' % (ip, ip)
	if args.ports:
		cmd += ' -p ' + args.ports
	results = fcmdoutput(cmd).split('\n')
	for line in results:
		if 'report for' in line:
			final += ' [H] Hostname: ' + line.split('for')[1].split(' ')[1]\
			 + '\n'
		if 'OS details' in line:
			final += ' [O] ' + line + '\n'
		if 'open' in line or 'filtered' in line:
			if not 'Not shown:' in line and not 'closed' in line:
				final += ' [S] ' + line + '\n'
	final += '\n [*] Scan results exported to results/' + ip + '.xml\n'
	return final

def fcmdoutput(cmd):
	return Popen(cmd.split(' '), stdout=PIPE).communicate()[0]

def fsearchsploit(terms):
	for term in terms:
		print '\n' + fcmdoutput('searchsploit ' + term)

def flive(hosts):
	print '\n [*] Starting ping scan of range ' + hosts
	lhosts = []
	live = fcmdoutput('nmap -PR -sn %s' % hosts).split('\n')
	print ' [*] Live Hosts:'
	for line in live:
		if 'report' in line:
			lhosts.append(line.split('(')[1][:-1])
			print ' [>]' + line.split('for')[1]
	print
	return lhosts

def fgetns(host):
	nsserv = []
	nsout = ' [0o] Starting enumeration of ' + cleanurl + '\n [*] Nameservers:\n'
	results = fcmdoutput('dig ns %s' % host).split('\n')
	for line in results:
		if 'NS' in line and ';' not in line: 
			nsserv.append(line.split('\t')[5][:-1])
	for ns in nsserv:
		nsout += ' [*] ' + ns + ' --> ' + socket.gethostbyname(ns) + '\n'\
		+ fzonetransfer(ns, cleanurl)
	return nsout


def fzonetransfer(ns, host):
	results = fcmdoutput('dig @%s %s axfr' % (ns, host)).split('\n')
	for line in results:
		if 'failed' in line or 'communications' in line or 'refused' in line:
			return ' [x] Zone transfer failed\n'
	return ' [!] Zone tansfer success!\n' + '\n'.join(results)

def fnslookup(host):
	sortedlist = []
	try:
		iplist = socket.getaddrinfo(host, 80)
		for group in iplist:
			sortedlist.append(group[4][0])
		return list(set(sortedlist))
	except:
		pass

def fwhois(ip):
	whoisresults = []
	whoislist = fcmdoutput('whois ' + ip).split('\n')
	for line in whoislist:
		whoisdata = ("desc" in line.lower() or "country" in line.lower() 
			or "orgname" in line.lower() or "netname" in line.lower())
		if whoisdata:
			whoisresults.append(line.strip('\n'))
	return ip + '\n' + '\n'.join(whoisresults)

def fdnsresolve(host):
	dnsout = ''
	try:
		for ip in fnslookup(host):
			if ip != ignoreip:
				dnsout += '\n [*] ' + host + ' --> ' + fwhois(ip)
	except:
		pass
	return dnsout

if getuid() != 0:
		print ' [!] No root, no play! Quitting...'
		quit()

if not path.exists('results'):
	mkdir('results')

if not any(vars(args).values()):
	parser.print_help() 
	exit()

if args.livehosts:
	flive(args.livehosts)

if args.url:
	subs = [ 'www', 'www2', 'ftp', 'cpanel', 'mail', 'direct', 'direct-connect',
	'media', 'store' 'webmail', 'portal', 'forum', 'forums', 'admin', 'vpn',
	'proxy', 'firewall', 'mx', 'pop3', 'router', 'owa', 'proxy', 'intranet' ]
	finalresult = ''
	try: # Check if the ISP hijacks DNS requests, so we can ignore them.
		ignoreip = socket.gethostbyname('notareal.website')
	except:
		ignoreip = ''
	cleanurl = '.'.join(args.url.split('.')[-2:])
	try:
		getnsdata = fgetns(cleanurl)
	except:
		print ' [*] Domain does not exist!'
		exit()
	print getnsdata
	finalresult += getnsdata
	for sub in subs:
		result = fdnsresolve(sub + '.' + args.url)
		if result:
			print result
			finalresult += result
	with open('results/%s.txt' % (cleanurl), 'w') as output:
		output.write(finalresult + '\n')
	print '\n [*] Scan results exported to results/' + cleanurl + '.txt\n'

if args.servicescan:
	ip = args.servicescan
	if '/' in ip or '-' in ip or ',' in ip:
		for ip in flive(ip):
			print fscan(ip)
	else:
		print fscan(ip)

if args.searchsploit:
	fsearchsploit(raw_input(" [>] Enter the terms to search separated by ','\n"\
	"eg: samba windows,proftpd 1.3.2 linux,unreal ircd,apache\n > ").split(','))
