#!/usr/bin/python
#
# Script to Find Info on each unique device discovered by part of the NetScan script
#

import psycopg2
import sys
import pprint
import subprocess
import os

#Setup Database Connection
try:
            conn_string = "host='192.168.0.44' dbname='netman' user='netman' password='netman'"
            conn = psycopg2.connect(conn_string)
            print "SUCCESS: Database Connection Established"
except:
            print "ERROR: I am unable to connect to the database"

cursor = conn.cursor()

#Obtain all unique MAC address entries from DB and place into list
cursor.execute('SELECT DISTINCT "MAC" from "NetScan";')
MAClist = cursor.fetchall()

#loop through MAClist and obtain info on each device. Insert info into database
MAClistLength = len(MAClist)
Counter = 0

Counter < MAClistLength
while (Counter < MAClistLength):
    MAC = MAClist[Counter]
    print MAC
    Counter += 1
