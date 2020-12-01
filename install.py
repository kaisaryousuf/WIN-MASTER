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
import shutil

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Display banner.
# Modified: N/A
# -------------------------------------------------------------------------------------

os.system("clear")
print("\t\t ____   ___   ____ _   _ _____      _    ____ _____ _   _ _____   ")
print("\t\t|  _ \ / _ \ / ___| | | | ____|    / \  / ___| ____| \ | |_   _|  ")
print("\t\t| |_) | | | | |  _| | | |  _|     / _ \| |  _|  _| |  \| | | |    ")
print("\t\t|  _ <| |_| | |_| | |_| | |___   / ___ \ |_| | |___| |\  | | |    ")
print("\t\t|_| \_\\\\___/ \____|\___/|_____| /_/   \_\____|_____|_| \_| |_|  ") 
print("\t\t                                                                  ")
print("\t\t      BY TERENCE BROADBENT BSc CYBERSECURITY (FIRST CLASS)    \n\n")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Install basic system requirements.
# Modified: N/A
# -------------------------------------------------------------------------------------

print("[*] Installing Rogue Agent system requirements...")

os.system("apt-get install seclists -y > log.tmp 2>&1")
os.system("apt-get install python3-pip -y >> log.tmp 2>&1")
os.system("apt-get install python3-ldap -y >> log.tmp 2>&1")
os.system("apt-get install gobuster -y >> log.tmp 2>&1")
os.system("apt-get install crackmapexec -y >> log.tmp 2>&1")
os.system("apt-get install exiftool -y >> log.tmp 2>&1")
os.system("apt-get install rlwrap -y >> log.tmp 2>&1")
os.system("apt-get install xdotool -y >> log.tmp 2>&1")
os.system("gem install evil-winrm >> log.tmp 2>&1")
os.system("pip3 install kerbrute >> log.tmp 2>&1")
os.system("pip3 install smtp-user-enum >> log.tmp 2>&1")
os.system("pip3 install termcolor >> log.tmp 2>&1")
os.system("pip3 install adidnsdump >> log.tmp 2>&1")
os.system("git clone https://github.com/ropnop/windapsearch.git >> log.tmp 2>&1")
os.system("mv windapsearch/windapsearch.py /usr/share/doc/python3-impacket/examples/windapsearch.py >> log.tmp 2>&1")
shutil.rmtree("windapsearch")

print("[+] Good Job!! Rogue Agent system requirements successfully installed...")

#Eof
