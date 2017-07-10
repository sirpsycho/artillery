#!/usr/bin/python

### This script summarizes the honeypot log and sends the results to
### the email address defined in the config file. This should be set
### to run via crontab every night at 23:59 in order to accurately
### summarize each day.


## Imports

from datetime import date
from src.core import *


## Variables

logfile = '/var/artillery/logs/honeypot.log'
today = str(date.today())

# these variables reference the index of each item in the honeypot log
loc_date = 0
loc_time = 1
loc_ip = 5
loc_port = 8
loc_country = 11


## Functions

# return a dictionary with IP as the key and frequency as the value
def get_freq_dict(log):
    freq_dict = {}
    for line in log:
        ip = line.split()[loc_ip]
        if ip in freq_dict:
            freq_dict[ip] += 1
        else:
            freq_dict[ip] = 1
    return freq_dict

# sorts a dictionary and returns a list of the "num" most frequent IPs
def get_top_ips(freq_dict, num):
    freq_list = []
    for key in freq_dict:
        freq_list.append([key, freq_dict[key]])
    sorted_list = sorted(freq_list, key=lambda x: x[1], reverse=True)[:num]
    top_ips = []
    for item in sorted_list:
        top_ips.append(item[0])
    return top_ips

# returns the frequency of a given IP in the honeypot log
def get_freq(ip, log):
    freq = 0
    for line in log:
        if ip in line:
            freq += 1
    return freq

# returns the country code corresponding to a given IP
def get_country(ip, log):
    country = "n/a"
    for line in log:
        if ip in line:
            try:
                country = line.split()[loc_country]
            except:
                country = "n/a"
            if not country == "n/a" and not "-" in country:
                break
    return country

# returns the first date/time that an IP appears in the log
def first_seen(ip, log):
    date = ""
    for line in log:
        if ip in line:
            date = line.split()[loc_date] + " " + line.split()[loc_time]
            break
    return date


## Execute

# create two variables, the full log and the log filtered on today's date
with open(logfile, 'r') as f:
    log = []
    log_today = []
    for line in f:
        log.append(line)
        if line.split()[loc_date] == today:
            log_today.append(line)

# get the 10 most frequent IPs from today's log data (10 can be changed to whatever)
freq_dict = get_freq_dict(log_today)
top_ips_today = get_top_ips(freq_dict, 10)

# create a list of IPs that have been seen today that have also been seen previously
reoccur = []
for ip in freq_dict:
    for line in log:
        if ip in line and not line.split()[loc_date] == today:
            reoccur.append(ip)
            break

# begin concatenating the email content
summary = ""
summary += "Today's Top Hits:\n\n"

for ip in top_ips_today:
    summary += "%s - %s (%s)" % (get_freq(ip, log_today), ip, get_country(ip, log))
    if ip in reoccur: summary += " *\n"
    else: summary += "\n"

summary += "\n* this IP has been logged before today\n\n\n"
summary += "Today's Stats:\n\n"
summary += "Total hits: %s\n" % len(log_today)
summary += "Total distinct IPs: %s\n" % len(freq_dict)
summary += "Reoccuring IPs: %s\n" % len(reoccur)
summary += "\n\nIP Details:\n\n"

for ip in top_ips_today:
    summary += "%s\n" % ip
    summary += "First seen: %s\n" % first_seen(ip, log)
    summary += "Hits (today / total): %s / %s\n" % (get_freq(ip, log_today), get_freq(ip, log))
    summary += "Country: %s\n\n" % get_country(ip, log)

### Debug:
#print summary

subject = "Summary for %s" % today

warn_the_good_guys(subject, summary)
