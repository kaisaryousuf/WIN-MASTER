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
# Details : Set system colours.
# Modified: N/A
# -------------------------------------------------------------------------------------

Red    = '\e[1;91m'
Yellow = '\e[1;93m'
Reset  = '\e[0m'

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
# Details : Display product banner. 
# Modified: N/A
# -------------------------------------------------------------------------------------

os.system("clear")
os.system("echo '" + Red + "'")
print("\t\t\t\t\t\t ____   ___   ____ _   _ _____      _    ____ _____ _   _ _____   ")
print("\t\t\t\t\t\t|  _ \ / _ \ / ___| | | | ____|    / \  / ___| ____| \ | |_   _|  ")
print("\t\t\t\t\t\t| |_) | | | | |  _| | | |  _|     / _ \| |  _|  _| |  \| | | |    ")
print("\t\t\t\t\t\t|  _ <| |_| | |_| | |_| | |___   / ___ \ |_| | |___| |\  | | |    ")
print("\t\t\t\t\t\t|_| \_\\\\___/ \____|\___/|_____| /_/   \_\____|_____|_| \_| |_|  ") #
os.system("echo '" + Yellow + "'")
print("\t\t\t\t\t\t               T R E A D S T O N E  E D I T I O N                \n")
os.system("echo '" + Red + "'")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Create program banners.
# Modified: N/A
# -------------------------------------------------------------------------------------

print("[*] Installing rogue agent, please wait...\n")
print("    " + "_"*72 + " PROGRESS BAR " + "_"*72)
print_no_newline("    ")

if not os.path.exists("ROGUEAGENT"):
   os.system("mkdir ROGUEAGENT"); bar()
os.chdir("ROGUEAGENT"); bar()

with open("banner1.txt","w") as banner:
   banner.write("\t\t\t\t\t\t ____   ___   ____ _   _ _____      _    ____ _____ _   _ _____  \n")
   banner.write("\t\t\t\t\t\t|  _ \ / _ \ / ___| | | | ____|    / \  / ___| ____| \ | |_   _| \n")
   banner.write("\t\t\t\t\t\t| |_) | | | | |  _| | | |  _|     / _ \| |  _|  _| |  \| | | |   \n")
   banner.write("\t\t\t\t\t\t|  _ <| |_| | |_| | |_| | |___   / ___ \ |_| | |___| |\  | | |   \n")
   banner.write("\t\t\t\t\t\t|_| \_\\\\___/ \____|\___/|_____| /_/   \_\____|_____|_| \_| |_| \n") 
   banner.write("\t\t\t\t\t\t                                                                 \n")
   banner.write("\t\t\t\t\t\t      BY TERENCE BROADBENT BSc CYBERSECURITY (FIRST CLASS)     \n\n")
bar()

with open("banner2.txt", "w") as banner:
   banner.write("ENUMERATION\t\tSHELLS\t\t\tRUNNING PROCESSES\t\tCOMMUNICATIONS\t\tCORE EXPLOITS\n")
   banner.write("---------------------------------------------------------------------------------------------------------------------------------------------------------\n")
   banner.write("jawsenum.ps1\t\tmeterpreter.exe\t\tpowerup.ps1\t\t\tnc64.exe\t\tmimidump.ps1\n")
   banner.write("sharphound.ps1\t\twebshell.php\t\tpowercat.ps\t\t\tplink64.exe\t\tmimikatz.ps1\n")
   banner.write("sharphound.exe\t\tmyshell.php\t\tpowerview.ps1\t\t\tchisel64.exe\t\twinpwn.ps1\n")
   banner.write("winpeas32.exe\t\timage.php.jpg\t\tpowermad.ps1\t\t\ttest_clsid.bat\t\tlovelypotato.ps1\n")
   banner.write("winpeas64.exe\t\t\t\t\tprocdump32.exe\t\t\trogueoxidresolver.exe\troguepotato.exe\n")
   banner.write("rubeus.exe\t\t\t\t\tprocdump64.exe\t\t\t\t\t\tmimikatz64.exe\n")
   banner.write("nmapsetup.exe\t\t\t\t\t\t\t\t\t\t\t\tmimikatz32.exe\n")
   banner.write("---------------------------------------------------------------------------------------------------------------------------------------------------------\n")
   banner.write("coffee.sh\t\tlinpayload.elf\t\tpspy32\t\t\t\t\t\t\tnaughtycowcompile.sh\n")
   banner.write("linpeas.sh\t\twebshell.php\t\tpspy64\t\t\t\t\t\t\tnaughycow.c\n")
   banner.write("linenum.sh\n")
   banner.write("linenumplus.sh\n")
   banner.write("linpe.sh\n")
bar()

with open("banner3.txt", "w") as banner:
   banner.write("\t\t\t\t\t\t ____  __  __ ____    ____  _____ ______     _______ ____   \n") 
   banner.write("\t\t\t\t\t\t/ ___||  \/  | __ )  / ___|| ____|  _ \ \   / / ____|  _ \  \n")
   banner.write("\t\t\t\t\t\t\___ \| |\/| |  _ \  \___ \|  _| | |_) \ \ / /|  _| | |_) | \n")
   banner.write("\t\t\t\t\t\t ___) | |  | | |_) |  ___) | |___|  _ < \ V / | |___|  _ <  \n")
   banner.write("\t\t\t\t\t\t|____/|_|  |_|____/  |____/|_____|_| \_\ \_/  |_____|_| \_\ \n")
   banner.write("\t\t\t\t\t\t                                                            \n")
   banner.write("\t\t\t\t\t\t  BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)   \n\n")
bar()

with open("banner4.txt", "w") as banner:
   banner.write("\t\t\t\t\t\t __  __ _____ _____ _____ ____  ____  ____  _____ _____ _____ ____   \n")
   banner.write("\t\t\t\t\t\t|  \/  | ____|_   _| ____|  _ \|  _ \|  _ \| ____|_   _| ____|  _ \  \n")
   banner.write("\t\t\t\t\t\t| |\/| |  _|   | | |  _| | |_) | |_) | |_) |  _|   | | |  _| | |_) | \n")
   banner.write("\t\t\t\t\t\t| |  | | |___  | | | |___|  _ <|  __/|  _ <| |___  | | | |___|  _ <  \n") 
   banner.write("\t\t\t\t\t\t|_|  |_|_____| |_| |_____|_| \_\_|   |_| \_\_____| |_| |_____|_| \_\ \n")
   banner.write("\t\t\t\t\t\t                                                                     \n")
   banner.write("\t\t\t\t\t\t       BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)       \n\n")
bar()

with open("banner5.txt", "w") as banner:
   banner.write("\t\t\t\t  ____  ___    ____  _   _ ___ ____  _   _ ___ _   _  ____ \n")
   banner.write("\t\t\t\t / ___|/ _ \  |  _ \| | | |_ _/ ___|| | | |_ _| \ | |/ ___|\n")
   banner.write("\t\t\t\t| |  _| | | | | |_) | |_| || |\___ \| |_| || ||  \| | |  _ \n")
   banner.write("\t\t\t\t| |_| | |_| | |  __/|  _  || | ___) |  _  || || |\  | |_| |\n")
   banner.write("\t\t\t\t \____|\___/  |_|   |_| |_|___|____/|_| |_|___|_| \_|\____|\n")
   banner.write("\t\t\t\t                                                           \n")
   banner.write("\t\t\t\t   BY TERENCE BROADBENT BSc CYBERSECURITY (FIRST CLASS)  \n\n")

os.chdir(".."); bar()

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Install system requirements.
# Modified: N/A
# -------------------------------------------------------------------------------------

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

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Install windows and linux exploits
# Modified: N/A
# -------------------------------------------------------------------------------------

if not os.path.exists("TREADSTONE"):
   os.system("mkdir TREADSTONE"); bar()
os.chdir("TREADSTONE"); bar()
os.system("wget https://download.sysinternals.com/files/Procdump.zip -O Procdump.zip > log.tmp 2>&1"); bar()
os.system("unzip Procdump.zip >> log.tmp 2>&1"); bar()
if os.path.exists("Procdump.zip"):
   os.remove("Procdump.zip"); bar()
os.remove("Eula.txt"); bar()
os.remove("procdump64a.exe"); bar()
os.system("wget 'https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases/winPEASx64.exe' -O winpeas64.exe >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases/winPEASx86.exe' -O winpeas32.exe >> log.tmp 2>&1"); bar()
#os.system("wget 'https://github.com/BloodHoundAD/BloodHound/raw/master/Ingestors/SharpHound.exe' -O sharphound.exe >> log.tmp 2>&1")
#os.system("wget 'https://github.com/BloodHoundAD/BloodHound/raw/master/Ingestors/SharpHound.ps1' -O sharphound.ps1 >> log.tmp 2>&1")
os.system("git clone https://github.com/TsukiCTF/Lovely-Potato.git >> log.tmp 2>&1"); bar()
os.system("mv ./Lovely-Potato/Invoke-LovelyPotato.ps1 ./lovelypotato.ps1 >> log.tmp 2>&1"); bar()
os.system("mv ./Lovely-Potato/JuicyPotato-Static.exe ./juicypotato.exe >> log.tmp 2>&1"); bar()
os.system("mv ./Lovely-Potato/test_clsid.bat ./ >> log.tmp 2>&1"); bar()
os.remove("./Lovely-Potato/README.md"); bar()
shutil.rmtree("Lovely-Potato"); bar()
os.system("wget 'https://github.com/antonioCoco/RoguePotato/releases/download/1.0/RoguePotato.zip' -O RoguePotato.zip >> log.tmp 2>&1"); bar()
os.system("unzip RoguePotato.zip >> log.tmp 2>&1"); bar()
os.remove("RoguePotato.zip"); bar()
os.system("mv ./RogueOxidResolver.exe ./rogueoxidresolver.exe >> log.tmp 2>&1"); bar()
os.system("mv ./RoguePotato.exe ./roguepotato.exe >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/411Hall/JAWS/raw/master/jaws-enum.ps1' -O jawsenum.ps1 >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/besimorhino/powercat/raw/master/powercat.ps1' -O powercat.ps1 >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/HarmJ0y/PowerUp/raw/master/PowerUp.ps1' -O powerup.ps1 >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/S3cur3Th1sSh1t/WinPwn/raw/master/WinPwn.ps1' -O winpwn.ps1 >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/PowerShellMafia/PowerSploit/raw/master/Exfiltration/Out-Minidump.ps1' -O mimidump.ps1 >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/PowerShellMafia/PowerSploit/raw/master/Exfiltration/Invoke-Mimikatz.ps1' -O mimilatz.ps1 >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/PowerView.ps1' -O powerview.ps1 >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/Kevin-Robertson/Powermad/raw/master/Powermad.ps1' -O powermad.ps1 >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/jpillora/chisel/releases/download/v1.7.2/chisel_1.7.2_windows_amd64.gz' -O chisel.gz >> log.tmp 2>&1"); bar()
os.system("gunzip chisel.gz"); bar()
os.system("mv chisel chisel64.exe >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/jpillora/chisel/releases/download/v1.7.2/chisel_1.7.2_windows_386.gz' -O chisel.gz >> log.tmp 2>&1"); bar()
os.system("gunzip chisel.gz"); bar()
os.system("mv chisel chisel32.exe >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe' -O rubeus.exe >> log.tmp 2>&1"); bar()
os.system("wget 'https://nmap.org/dist/nmap-7.80-setup.exe' -O nmapsetup.exe >> log.tmp 2>&1"); bar()
os.system("cp /usr/share/windows-resources/mimikatz/Win32/mimikatz.exe ./mimikatz32.exe >> log.tmp 2>&1"); bar()
os.system("cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe ./mimikatz64.exe >> log.tmp 2>&1"); bar()
os.system("cp /usr/share/windows-resources/binaries/nc.exe nc64.exe >> log.tmp 2>&1"); bar()
os.system("cp /usr/share/windows-resources/binaries/plink.exe plink64.exe >> log.tmp 2>&1"); bar()
os.system("wget 'https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php' -O webshell.php >> log.tmp 2>&1"); bar()
os.system("wget 'https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php' -O myshell.php >> log.tmp 2>&1"); bar()
os.system("wget 'https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh' -O linenum.sh >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh' -O linenumplus.sh >> log.tmp 2>&1"); bar()
os.system("wget 'https://raw.githubusercontent.com/Adlemann/linPE/master/linpe.sh' -O linpe.sh >> log.tmp 2>&1"); bar()
os.system("wget 'https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh' -O linpeas.sh >> log.tmp 2>&1"); bar()
os.system("wget 'https://raw.githubusercontent.com/Arr0way/linux-local-enumeration-script/master/linux-local-enum.sh' -O coffee.sh >> log.tmp 2>&1"); bar()
os.system("wget 'https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php' -O webshell.php >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32' -O pspy32 >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64' -O pspy64 >> log.tmp 2>&1"); bar()
os.system("wget 'https://raw.githubusercontent.com/kkamagui/linux-kernel-exploits/master/kernel-4.4.0-31-generic/CVE-2016-5195/compile.sh' -O naughtycowcompile.sh >> log.tmp 2>&1"); bar()
os.system("wget 'https://raw.githubusercontent.com/kkamagui/linux-kernel-exploits/master/kernel-4.4.0-31-generic/CVE-2016-5195/naughtyc0w.c' -O naughthycow.c >> log.tmp 2>&1"); bar()
os.system("wget 'https://github.com/jpillora/chisel/releases/download/v1.7.2/chisel_1.7.2_linux_amd64.gz' -O chisel_1.7.2_linux_amd64.gz >> log.tmp 2>&1"); bar()
os.system("gzip -d chisel_1.7.2_linux_amd64.gz >> log.tmp 2>&1"); bar()
os.system("mv chisel_1.7.2_linux_amd64 chisel.linux64 >> log.tmp 2>&1"); bar()
os.chdir(".."); bar()

print("\n\n[+] Rogue agent successfully installed...")
os.system("echo '" + Reset + "'")
#Eof
