apt-get install seclists
apt-get install gnome-terminal
apt-get install python3-pip
apt-get install python3-ldap
apt-get install gobuster
gem install evil-winrm
pip3 install kerbrute
git clone https://github.com/ropnop/windapsearch.git
cd ./windapsearch
mv ./windapsearch.py /usr/share/doc/python3-impacket/examples/windapsearch.py
cd ..
rm -r windapsearch
python3 -m pip install pipx
pipx ensurepath
pipx install crackmapexec
