#!/usr/bin/python
#
# Script to Find Info on each unique device discovered by part of the NetScan script
#

import psycopg2
import sys
import pprint
import subprocess
import os
from ConfigParser import SafeConfigParser
import urllib2
import json
import codecs
import sched
import time
import datetime
import logging

#Setup logging
logging.basicConfig(filename='../logs/DevInfo.log',level=logging.DEBUG, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')


#Import varibales from NetMan.conf
Config = SafeConfigParser()
Config.read('../conf/NetMan.conf')

#Set CIDR variable from conf file
CIDR =  Config.get('config', 'network')

#Setup Database Connection
try:
            conn_string = "host='localhost' dbname='netman' user='netman' password='netman'"
            conn = psycopg2.connect(conn_string)
            logging.info('SUCCESS: Database Connection Established')
except:
            logging.warning('ERROR: I am unable to connect to the database')

cursor = conn.cursor()

s = sched.scheduler(time.time, time.sleep)
def do_something(sc): 
    s.enter(86400, 1, do_something, (sc,))

    logging.info('SUCCESS: Scheduler starting')

    #Obtain all unique MAC address entries from DB and place into list, MAClistPre initially pulls all entries but with extract characters, MAClist then removes these characters
    cursor.execute('SELECT DISTINCT "MAC" from "NetScan";')
    MAClistPre = cursor.fetchall()
    MAClist = list(sum(MAClistPre, ()))


    #loop through MAClist and obtain info on each device. Insert info into database
    MAClistLength = len(MAClist)
    Counter = 0

    while (Counter < MAClistLength):
        #Pull first MAC from the list
        MAC = MAClist[Counter]
        # Cast MAC as String
        MAC = str(MAC)
        logging.debug('MAC Address: %s',  MAC)
        

        #Obtain latest IP assigned to MAC Address
        IPextract_CMD = "/usr/sbin/arp -n | grep '" +  MAC + "' | awk '{print $1}'"
        IPext_CMD_Output = subprocess.Popen([IPextract_CMD], shell=True, stdout=subprocess.PIPE).stdout

        DevIP = IPext_CMD_Output.read().splitlines()

        if len(DevIP) > 0:
            DevIP = DevIP[0]
        else:
            DevIP = "UNKNOWN"
        #DevIPList[0] = DevIP
        logging.debug('IP: %s', DevIP)
        

        #Identify Device Hostname
        DevHostname_CMD = "/usr/bin/nmap -sL  " + CIDR + "| grep -w " + DevIP + " | awk '{print $5}'"
        DevHostname_CMD_Output = subprocess.Popen([DevHostname_CMD], shell=True, stdout=subprocess.PIPE).stdout
        DevHostname = DevHostname_CMD_Output.read().splitlines()

        if len(DevHostname) > 0:
            DevHostname = DevHostname[0]
        else:
            DevHostname = "UKNOWN"
        logging.debug('Hostname: %s', DevHostname)


        #Identify Device Operating System
        DevOS_CMD = "/usr/bin/sudo /usr/bin/nmap -O -T5 " + DevIP + " | grep Running"
        
        if DevIP is "UNKNOWN":
            DevOS = "UNKNOWN"
        else:   
            DevOS_CMD_Output = subprocess.Popen([DevOS_CMD], shell=True, stdout=subprocess.PIPE).stdout
            DevOS = DevOS_CMD_Output.read().splitlines()

        if isinstance(DevOS, list) and len(DevOS) > 0:
                DevOS = DevOS[0]
        else:
                DevOS = "UNKNOWN"
        
        DevOS = str(DevOS)
        logging.debug('OS: %s', DevOS)

        
        #Identify interface manufacturer from macvendors
        url = "http://macvendors.co/api/"
        request = urllib2.Request(url+MAC, headers={'User-Agent' : "API Browser"})
        response = urllib2.urlopen( request )
        reader = codecs.getreader("utf-8")
        MACLookupResponse = json.load(reader(response))
        #print type(MACLookupResponse)

        if MACLookupResponse['result'].has_key('company'):
            MACVendor =  MACLookupResponse['result']['company']
        else:
            MACVendor = "UNKNOWN"  
            
        logging.debug('Interface Vendor: %s',  MACVendor)
        
        
        #Identify Open Ports on Device
        Scan_CMD = "sudo nmap -n -PN " + DevIP + " | grep -w open | awk '{print $1}'"
        if DevIP is "UNKNOWN":
            DevPorts = "UNKNOWN"
        else:
            Scan_CMD_Output = subprocess.Popen([Scan_CMD], shell=True, stdout=subprocess.PIPE).stdout
            DevPorts = Scan_CMD_Output.read().splitlines()
            DevPorts = '[%s]' % ', '.join(map(str, DevPorts))

        
        logging.debug('Open Ports: %s', DevPorts)
        
        Counter += 1

s.enter(86400, 1, do_something, (s,))
s.run()
