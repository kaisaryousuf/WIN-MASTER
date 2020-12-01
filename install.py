#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#         PYTHON3 SCRIPT FILE FOR THE REMOTE ANALYSIS OF COMPUTER NETWORKS
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
import os.path
import shutil

def banner():
   print("\t\t ____   ___   ____ _   _ _____      _    ____ _____ _   _ _____   ")
   print("\t\t|  _ \ / _ \ / ___| | | | ____|    / \  / ___| ____| \ | |_   _|  ")
   print("\t\t| |_) | | | | |  _| | | |  _|     / _ \| |  _|  _| |  \| | | |    ")
   print("\t\t|  _ <| |_| | |_| | |_| | |___   / ___ \ |_| | |___| |\  | | |    ")
   print("\t\t|_| \_\\\\___/ \____|\___/|_____| /_/   \_\____|_____|_| \_| |_|  ") 
   print("\t\t                                                                  ")
   print("\t\t      BY TERENCE BROADBENT BSc CYBERSECURITY (FIRST CLASS)        \n\n")
   return

# -------------------------------------------------------------------------------------
# SYSTEM REQUIREMENTS
# -------------------------------------------------------------------------------------

os.system("clear")
banner()
print("[*] Installing Rogue Agent System Requirements...\n")

os.system("apt-get install seclists -y")
os.system("apt-get install python3-pip -y")
os.system("apt-get install python3-ldap -y")
os.system("apt-get install gobuster -y")
os.system("apt-get install crackmapexec -y")
os.system("apt-get install exiftool -y")
os.system("apt-get install rlwrap -y")
os.system("apt-get install xdotool -y")

os.system("gem install evil-winrm")

os.system("pip3 install kerbrute")
os.system("pip3 install smtp-user-enum")
os.system("pip3 install termcolor")
os.system("pip3 install adidnsdump")

os.system("git clone https://github.com/ropnop/windapsearch.git")
os.system("mv windapsearch/windapsearch.py /usr/share/doc/python3-impacket/examples/windapsearch.py")
shutil.rmtree("windapsearch")t("[+] Loading exploit files...")

print("[+] Good Job!! Rogue Agent System Requirements Installed...")

#Eof
