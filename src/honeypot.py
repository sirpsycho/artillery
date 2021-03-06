#!/usr/bin/python
#
# this is the honeypot stuff
#
#
# needed for backwards compatibility of python2 vs 3 - need to convert to threading eventually
try: import thread
except ImportError: import _thread as thread
import socket
import sys
import re
import subprocess
import time
try: import SocketServer
except ImportError: import socketserver as SocketServer
import os
import random
import datetime
from src.core import *

# port ranges to spawn pulled from config
ports = read_config("PORTS")
# check to see what IP we need to bind to
bind_interface = read_config("BIND_INTERFACE")
honeypot_ban = is_config_enabled("HONEYPOT_BAN")
honeypot_autoaccept = is_config_enabled("HONEYPOT_AUTOACCEPT")

# main socket server listener for responses


class SocketListener((SocketServer.BaseRequestHandler)):

    def handle(self):
        pass

    def setup(self):
        # hehe send random length garbage to the attacker
        length = random.randint(5, 30000)

        # fake_string = random number between 5 and 30,000 then os.urandom the
        # command back
        fake_string = os.urandom(int(length))

        # try the actual sending and banning
        try:
            self.request.send(fake_string)
            ip = self.client_address[0]
            if is_valid_ipv4(ip):
                check_whitelist = is_whitelisted_ip(ip)
                # ban the mofos
                if check_whitelist == 0:
                    now = str(datetime.datetime.today())
                    port = self.server.server_address[1]

		    log = "/var/artillery/logs/honeypot.log"
		    email = False
		    if ip in open('/var/artillery/banlist.txt').read():
			prev_num_of_ips = count_occurrences(ip, log)
			total_seen_ips = prev_num_of_ips + 1
			first_seen = str(get_first_time(ip, log))
			repeat_msg = "[!] NOTE: This IP address has already been detected and added to banlist.txt BEFORE this incident.\nThis IP has been logged %s times before this incident.\nFirst seen on: %s" % (prev_num_of_ips, first_seen)
			## Only send email notifications for hits of 20, 50, 100, etc.
			if prev_num_of_ips == 19 or prev_num_of_ips == 49 or prev_num_of_ips == 99 or prev_num_of_ips == 199 or prev_num_of_ips == 299 or prev_num_of_ips == 399 or prev_num_of_ips == 499 or prev_num_of_ips == 999:
			    email = True
		    else:
			total_seen_ips = 1
			repeat_msg = "NOTE: This is the first time that this server has detected this IP address."

		    ban(ip)

		    location = get_location(ip)
		    country = get_country(location, ip, log)

                    subject = "[%s] Attack - IP: %s .. Port: %s .. Country: %s" % (
			total_seen_ips, ip, port, country)
		    with open("/var/artillery/logs/honeypot.log", "a") as myfile:
			myfile.write("%s - [%s] IP: %s .. Port: %s .. Country: %s\n" % (now, total_seen_ips, ip, port, country))
                    alert = ""
                    if honeypot_ban:
                        alert = "%s [!] Artillery has blocked (and blacklisted) the IP Address: %s for connecting to a honeypot restricted port: %s\n\nLocation info:\n%s\n\n%s" % (
                            now, ip, port, location, repeat_msg)
                    else:
                        alert = "%s [!] Artillery has detected an attack from IP address: %s for a connection on a honeypot port: %s\n\nLocation info:\n%s\n\n%s" % (
                            now, ip, port, location, repeat_msg)

		    if email == True:
                        warn_the_good_guys(subject, alert)

                    # close the socket
                    self.request.close()

                    # if it isn't whitelisted and we are set to ban
                    ban(ip)

        except Exception as e:
            print("[!] Error detected. Printing: " + str(e))
            pass

## Pull location info on an IP using the ipinfo API
def get_location(ip):
    curl_url = "ipinfo.io/" + ip
    proc = subprocess.Popen(["curl", curl_url], stdout=subprocess.PIPE)
    (location, err) = proc.communicate()
    return location

## Get the country code for a given IP
def get_country(location, ip, log):
    if "country" not in location:
	country = "n/a"
	with open(log) as f:
	    for line in f:
		if ip in line:
		    start = line.index('Country: ') + len('Country: ')
		    end = line.index("\n", start)
		    country = line[start:end]
		    if not country == 'n/a' and not "-" in country:
			country = "-%s-" % (country)
			break
	return country
    else:
	string = location.split('country\": \"',1)[1]
	string = string.rsplit('\",\n  \"loc',1)[0]
	return string

## Count how many times a string is listed in a file
def count_occurrences(string, file):
    f = open(file)
    contents = f.read()
    f.close()
    return contents.count(string)

## Get the timestamp on the first occurrence of an ip address
def get_first_time(ip, logfile):
    with open(logfile) as f:
	for line in f:
	    if ip in line:
		return line.rsplit(' - ', 1)[0]

# here we define a basic server
def listen_server(port, bind_interface):
    try:
        port = int(port)
        if bind_interface == "":
            server = SocketServer.ThreadingTCPServer(
                ('', port), SocketListener)
        else:
            server = SocketServer.ThreadingTCPServer(
                ('%s' % bind_interface, port), SocketListener)
        if honeypot_autoaccept:
            subprocess.Popen(
                "iptables -A ARTILLERY -p tcp --dport %s  -j ACCEPT" % port, shell=True).wait()
        server.serve_forever()
    # if theres already something listening on this port
    except Exception:
        # write a log if we are unable to bind to an interface
        write_log("[!] %s: Artillery was unable to bind to port: %s. This could be to an active port in use." % (
            grab_time(), port))
        pass

# check to see which ports we are using and ban if ports are touched


def main(ports, bind_interface):

        # pull the banlist path
    if os.path.isfile("check_banlist_path"):
        banlist_path = check_banlist_path()
        fileopen = file(banlist_path, "r")
        for line in fileopen:
            # remove any bogus characters
            line = line.rstrip()
            # ban actual IP addresses
            if honeypot_ban:
                whitelist = read_config("WHITELIST_IP")
                match = re.search(line, whitelist)
                if not match:
                        # ban the ipaddress
                    ban(line)
    # split into tuple
    ports = ports.split(",")
    for port in ports:
        thread.start_new_thread(listen_server, (port, bind_interface,))

# launch the application
main(ports, bind_interface)
