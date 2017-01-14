#!/usr/bin/python
#
# Script to Insert MAC Addresses from ARP table into DB
#

import psycopg2
import sys
import pprint
import subprocess
import os
from ConfigParser import SafeConfigParser

#Import varibales from NetMan.conf
Config = SafeConfigParser()
Config.read('../conf/NetMan.conf')

#Set CIDR variable from conf file
CIDR =  Config.get('config', 'network')


#Define subnet to scan
#CIDR = "192.168.0.0/24"

# ntp sync


#Setup Database Connection
try:
            conn_string = "host='192.168.0.44' dbname='netman' user='netman' password='netman'"
            conn = psycopg2.connect(conn_string)
            print "SUCCESS: Database Connection Established"
except:
            print "ERROR: I am unable to connect to the database"

cursor = conn.cursor()

#Execute a nmap IP layer scan to populate arp table
NMAP_CMD = "/usr/bin/nmap -sP " + CIDR
FNULL = open(os.devnull, 'w')
subprocess.call([NMAP_CMD], shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
print "SUCCESS: nmap executed"

#Print arp table and extract MAC Addresses

MACs = subprocess.Popen(["/usr/sbin/arp -a | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'"], shell=True, stdout=subprocess.PIPE).stdout
MAClist = MACs.read().splitlines()
print "SUCCESS: MAC Addresses Obtained from arp table"
#print "DEBUG: Print MAC List"
#print MAClist

#Insert MAC Addresses into DB NetScan Table

MAClistLength = len(MAClist)
Counter = 0

Counter < MAClistLength
while (Counter < MAClistLength):
    MAC = MAClist[Counter]
    query = """ INSERT INTO "NetScan" ("MAC") values ('""" + MAC  + """'); """
    cursor.execute(query)
    Counter += 1

#Commit data to database
conn.commit()

#DEBUG - PRINT NetScan Table
# execute our Query
# cursor.execute('select * from "NetScan"')
# retrieve the records from the database
# records = cursor.fetchall()
# pprint.pprint(records)
