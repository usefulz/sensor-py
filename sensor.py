#!/usr/bin/python3
# port scan without firing a shot
# note: you cannot use this for scanning RFC1918 IPs because this uses remote nmap proxies
# if you need to scan RFC1918 space, use nmap with the decoy option, or ARP scanning
import os
import sys
import requests
import json
import time
import scanless
import pprint

""" This scanner requests a remote scan from nmap online service providers, and then decodes the result of the scan into JSON """

class Target(object):

	ip = None
	open_ports_tcp = set()
	open_ports_udp = set()

	def __init__(self, ip):
		self.ip = ip
		return None

	def port_scan_tcp(self, ip):
		output = {}
		sl = scanless.Scanless()
		output = sl.scan(ip, scanner='viewdns')
		return self.parse(output['raw'])

	def parse(self, output):
		for line in output.split('\n'):
			if '/tcp' in line:
				port_str, state, service = line.split()
				if state == 'open':
					port, protocol = port_str.split('/')
					self.open_ports_tcp.add(abs(int(port)))
			if '/udp' in line:
				port_str, state, service = line.split()
				if state == 'open':
					port, protocol = port_str.split('/')
					self.open_ports_udp.add(abs(int(port)))
		return {'tcp': sorted(self.open_ports_tcp), 'udp': sorted(self.open_ports_udp)}

class Service(object):
	port = None
	proto = None
	description = None
	proper_name = None

	def __init__(self, port, proto, description, proper_name):
		self.port = int(port)
		self.proto = int(proto)
		self.description = str(description)
		self.proper_name = str(proper_name)
		return None

if __name__ == '__main__':

	target = Target(sys.argv[1])
	ports = target.port_scan_tcp(target)
	pstring = json.dumps(ports, separators=(',', ':'))
	pprint.pprint(pstring)

