#!/bin/bash
# coding:UTF-8

# -------------------------------------------------------------------------------------
#                           WINDOWS MASTER PROGRAM INSTALL
#                BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)
# -------------------------------------------------------------------------------------

apt-get install seclists -y
apt-get install python3-pip -y
apt-get install python3-ldap -y
apt-get install gobuster -y
apt-get install crackmapexec -y
gem install evil-winrm
pip3 install kerbrute
pip3 install smtp-user-enum
pip3 install termcolor 
git clone https://github.com/ropnop/windapsearch.git
cd ./windapsearch
mv ./windapsearch.py /usr/share/doc/python3-impacket/examples/windapsearch.py
cd ..
rm -r windapsearch

echo "I am all Done!!..."

#Eof
