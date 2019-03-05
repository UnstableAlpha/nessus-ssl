#! /usr/bin/python

import sys
import xml.etree.ElementTree as ET
import csv

# Nessus SSL Parser by James Burns (@Unstable_Alpha)
# Work in progress - not to be used without human validation

# Usage:
# ./nessus-ssl.py <.nessus-file-to-parse>

# Instruct script to open nessus file passed via the command line
nessus = ET.parse(sys.argv[1])
# Identify XML root
root = nessus.getroot()

# Designate nessus plugins to be extracted from .nessus
# Following can be changed to extract specific info, but output format will likely
# need to be amended
plugins = ["15901","26928","35291","42873","45411","51192","57582","65821","69551"]

# Hostlist (to be populated by parsing the .nessus file)
hostlist = []

# Define functions

# Obtain Original Nessus Report Name
def ReportName():
	for report in nessus.findall(".//Report"):
		reportname = report.get('name')
		print ""
		print "[+] Identified Nessus Report Name: " +str(reportname)
		print ""

# Obtain List of Hosts in Report
def ReportHosts():
	print ""
	for host in nessus.findall(".//ReportHost"):
		hostip = host.get('name')
		hostlist.append(hostip)
		print "[+] Identified Report Host:  " +hostip
	print ""
	# print hostlist

# Obtain List of Findings per-host
def HostIssues():
	print ""
	csvfile = open('Nessus-SSL.csv', 'w')
	writer = csv.writer(csvfile, delimiter=',')
	for item in nessus.findall(".//ReportHost"):
		hostip = item.get('name')
		for host in hostlist:
			if host == hostip:
				print "[+] Host: " + host
				for reportitem in item.findall(".//ReportItem"):
					pluginid = (reportitem.get('pluginID'))
					pluginname = (reportitem.get('pluginName'))
					pluginproto = (reportitem.get('protocol'))
					pluginport = (reportitem.get('port'))
					if pluginid in plugins:
						print ("[+] Identified Issue %s on port %s %s" % (pluginname, pluginproto, pluginport))
						pluginnet = pluginproto+pluginport
						writer.writerow([host, pluginname, pluginnet])
					print ""
	csvfile.close()

ReportName()
ReportHosts()
HostIssues()
