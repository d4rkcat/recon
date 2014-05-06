#!/usr/bin/python

import subprocess, socket, argparse

parser = argparse.ArgumentParser(prog='recon', usage='./recon.py [options]')
parser.add_argument('-u', "--url", type=str, help='nslookup, quick dns brute and whois info on url')
parser.add_argument('-s', "--servicescan", type=str, help='scan ip/range for services')
parser.add_argument('-l', "--livehosts", type=str, help='pingscan ip/range for live hosts')
parser.add_argument('-p', "--ports", type=str, help='port range for service scan')
parser.add_argument('-t', "--searchsploit", action="store_true", help='use searchsploit')
args = parser.parse_args()

def fscan(ips):
	fcmdoutput('mkdir -p results')
	for ip in ips:
		print ' [0o] Starting service scan of ' + ip
		cmd = 'nmap -sV -O ' + ip + ' -oX results/' + ip + '.xml'
		if args.ports:
			cmd += ' -p ' + args.ports
		results = fcmdoutput(cmd).split('\n')
		for line in results:
			if 'report for' in line:
				print ' [H] Hostname: ' + line.partition('for')[2].strip().split(' ')[0]
			if 'OS details' in line:
				print ' [O] ' + line
			if 'open' in line or 'filtered' in line:
				if not 'Not shown:' in line and not 'closed' in line:
					print ' [S] ' + line
		print '\n [*] Scan results exported to results/' + ip + '.xml\n'

def fcmdoutput(cmd):
	return subprocess.Popen(cmd.split(' '), stdout=subprocess.PIPE).communicate()[0]

def fsearchsploit(terms):
	for term in terms:
		print '\n' + fcmdoutput('searchsploit ' + term)

def flive(hosts):
	print '\n [*] Starting ping scan of range ' + hosts
	lhosts = []
	live = fcmdoutput('nmap -PR -sn ' + hosts).split('\n')
	for host in live:
		if 'report' in host:
			lhosts.append(host.partition('(')[2].strip(')'))
			print ' [>] Found alive host at ' + host.partition('(')[2].strip(')')
	print
	return lhosts

def fgetns(host):
	nsserv = []
	results = fcmdoutput('dig ns ' + host).split('\n')
	for line in results:
		if 'NS' in line and ';' not in line:
			nsserv.append(line.partition('NS')[2][:-1].strip('\t'))
	return nsserv

def fzonetransfer(ns, host):
	results = fcmdoutput('dig @' + ns + ' ' + host + ' axfr').split('\n')
	for line in results:
		if 'Transfer failed' in line or '; communications error' in line:
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
		if "desc" in line.lower() or "country" in line.lower() or "orgname" in line.lower() or "netname" in line.lower():
			whoisresults.append(line.strip('\n'))
	return ip + '\n' + '\n'.join(whoisresults)

def fdnsbrute(host):
	subs = [ 'www', 'ftp', 'cpanel', 'mail', 'direct', 'direct-connect', 'webmail', 'portal', 'forum', 'forums', 'admin' ]
	for sub in subs:
		look = sub + '.' + host
		try:
			for ip in fnslookup(look):
				if ip != ignoreip:
					print '\n [*] ' + look + ' --> ' + fwhois(ip)
		except:
			pass
	print

if not any(vars(args).values()):
	parser.print_help()
	exit()

if args.livehosts:
	flive(args.livehosts)

if args.url:
	try:
		ignoreip = socket.gethostbyname('notareal.website')	# Check if the ISP hijacks DNS requests, so we can ignore them.
	except:
		ignoreip = ''
	cleanurl = '.'.join(args.url.split('.')[-2:])
	print ' [0o] Starting enumeration of ' + cleanurl + '\n' + ' [*] Nameservers:\n'
	for ns in fgetns(cleanurl):
		print ' [*] ' + ns + ' --> ' + socket.gethostbyname(ns) + '\n' + fzonetransfer(ns, cleanurl)
	fdnsbrute(cleanurl)

if args.servicescan:
	if '/' in args.servicescan or '-' in args.servicescan or ',' in args.servicescan:
		fscan(flive(args.servicescan))
	else:
		fscan(args.servicescan.split('\n'))

if args.searchsploit:
	fsearchsploit(raw_input(" [>] Enter the terms to search seperated by ',' eg: samba windows,proftpd 1.3.2 linux,unreal" \
	" ircd,apache\n > ").split(','))
