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
import sched
import time
import datetime
import logging


#Setup logging
logging.basicConfig(filename='../logs/NetScan.log',level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')


#Import varibales from NetMan.conf
Config = SafeConfigParser()
Config.read('../conf/NetMan.conf')

#Set CIDR variable from conf file
CIDR =  Config.get('config', 'network')

#Setup Database Connection
try:
            conn_string = "host='localhost' port='5432' dbname='netman' user='netman' password='netman'"
            conn = psycopg2.connect(conn_string)
            logging.info('SUCCESS: Database Connection Established')
except:
            logging.warning('ERROR: I am unable to connect to the database')

cursor = conn.cursor()

s = sched.scheduler(time.time, time.sleep)
def do_something(sc): 
    s.enter(600, 1, do_something, (sc,))

    logging.info('SUCCESS: Scheduler starting')
  
    #Execute a nmap IP layer scan to populate arp table
    NMAP_CMD = "/usr/bin/nmap -sP " + CIDR
    FNULL = open(os.devnull, 'w')
    subprocess.call([NMAP_CMD], shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
    logging.info('SUCCESS: nmap executed')

    MACs = subprocess.Popen(["/usr/sbin/arp -a | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'"], shell=True, stdout=subprocess.PIPE).stdout
    MAClist = MACs.read().splitlines()
    logging.info('SUCCESS: MAC Addresses Obtained from arp table')
    

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
    MAClistLength = str(MAClistLength)
    logging.info('SUCCESS: Inserting %s rows into database', MAClistLength)

s.enter(600, 1, do_something, (s,))
s.run()

