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
# Details : Create functional subroutines to be called from main.
# Modified: N/A
# -------------------------------------------------------------------------------------

def print_no_newline(string):
    import sys
    sys.stdout.write(string)
    sys.stdout.flush()
    return

def bar():
   print_no_newline('⬜')
   return

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

print("[*] Installing rogue agent, please wait...\n")
print("    _________ PROGRESS BAR _________")
print_no_newline("    ")
os.system("apt-get install seclists -y > log.tmp 2>&1"); bar()
os.system("apt-get install python3-pip -y >> log.tmp 2>&1"); bar()
os.system("apt-get install python3-ldap -y >> log.tmp 2>&1"); bar()
os.system("apt-get install gobuster -y >> log.tmp 2>&1"); bar()
os.system("apt-get install crackmapexec -y >> log.tmp 2>&1"); bar()
os.system("apt-get install exiftool -y >> log.tmp 2>&1"); bar()
os.system("apt-get install rlwrap -y >> log.tmp 2>&1"); bar()
os.system("apt-get install xdotool -y >> log.tmp 2>&1"); bar()
os.system("gem install evil-winrm >> log.tmp 2>&1"); bar()
os.system("pip3 install kerbrute >> log.tmp 2>&1"); bar()
os.system("pip3 install smtp-user-enum >> log.tmp 2>&1"); bar()
os.system("pip3 install termcolor >> log.tmp 2>&1"); bar()
os.system("pip3 install adidnsdump >> log.tmp 2>&1"); bar()
os.system("git clone https://github.com/ropnop/windapsearch.git >> log.tmp 2>&1"); bar()
os.system("mv windapsearch/windapsearch.py /usr/share/doc/python3-impacket/examples/windapsearch.py >> log.tmp 2>&1"); bar()
shutil.rmtree("windapsearch"); bar()
print("\n\n[+] Rogue agent successfully installed...")
#Eof
