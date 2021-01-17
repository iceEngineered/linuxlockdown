#!/bin/bash
#Guts written by Nathan pan
#Wrapper written by Curtis-Arnold-V
Red='\033[0;31m'
NC='\033[0m'
Green='\033[0;32m'
Blue='\033[0;34m'
echo -e "${Blue}
Written by Nathan Pan & Curtis M Arnold
Produced for CyberPatriot2020-2021 Season
Career and Technology Center, Frederick, MD, USA
Please do not run this if you don't know what you're doing.
${NC} "
if [ "$1" = "Help" ]
then
echo -e "${Red}Run with no more than one option at a time ${NC} "
echo "Full -Applock -Filelock - Userlock - Prework - Help"
echo -e "${Red}There  is  NO  WARRANTY, to the extent permitted by law.${NC}"
exit 0
fi
####################################LOG&BACKUP FILE####################################
if [ "$1" = "Full" || "Userlock" ]
touch ~/Desktop/Password.txt
echo -e "Use Custom Password or built-in?(y/n)"
read pwyn
if [ $pwyn == y ]
then
    echo "Password:  "
    read pw
    echo "$pw" > ~/Desktop/Password.txt
    echo "Password has been set as '$pw'."
else
    echo 'H=Fmcqz3M]}&rfC$F>b)' > ~/Desktop/Password.txt
    echo "Password has been set as 'H=Fmcqz3M]}&rfC$F>b)'."
fi

chmod 777 ~/Desktop/Password.txt
echo "Password file is on desktop. Copy password from the file."
declare -i numusers
declare -i numadminusers
declare -i numnewusers
declare -A users=()
declare -A adminusers=()
declare -A newusers=()
echo "How many users need to be added? ex: 5 "
echo -e "Use Custom Password or built-in?(y/n)"
echo "DONT FORGET TO INCLUDE THEM LATER"
read numnewusers
echo "How many non-admin users? ex: 5"
read numusers
echo "How many ADMIN users? ex: 5"
read numadminusers
echo "Want to remove every user you haven't mentioned? (y/n)"
read removeunknownusers
i=1
((numnewusers += 1))
while [[ $i -lt $numnewusers ]] ; do
     echo "enter name of user$i - "
     read newusers[$i]
     echo "newuser$i recorded as - ${newusers[$i]}  - "
    (( i += 1 ))
done
i=1
while [[ $i -lt $numnewusers ]] ; do
    newuser=${newusers[$i]}
    echo "newuser$i is $newuser "
    (( i += 1 ))
done
while [[ $i -lt $numadminusers ]] ; do
     echo "enter name of user$i - "
     read adminusers[$i]
     echo "adminuser$i recorded as - ${adminusers[$i]}  - "
    (( i += 1 ))
done
i=1
while [[ $i -lt $numadminusers ]] ; do
    adminuser=${adminusers[$i]}
    echo "adminuser$i is $adminuser "
    (( i += 1 ))
done
echo "Is ALL of that correct?? (y/n)"
read correct
if [ $correct = "n" ]
exit 0
fi
fi
if [ "$1" = "Full" || "Applock"]
then
echo "Does this machine need Samba?"
read sambaYN
echo "Does this machine need FTP?"
read ftpYN
echo "Does this machine need SSH?"
read sshYN
echo "Does this machine need Telnet?"
read telnetYN
echo "Does this machine need Mail?"
read mailYN
echo "Does this machine need Printing?"
read printYN
echo "Does this machine need MySQL?"
read dbYN
echo "Will this machine be a Web Server?"
read httpYN
echo "Does this machine need DNS?"
read dnsYN
echo "Does this machine need remote desktop capabilities?"
read rdpYN
fi


function prework(){
echo "Update every thing at end? y/n"
read update_y
touch ~/Desktop/Script.log
echo > ~/Desktop/Script.log
chmod 777 ~/Desktop/Script.log
mkdir -p ~/Desktop/backups
chmod 777 ~/Desktop/backups
cp /etc/group ~/Desktop/backups/
cp /etc/passwd ~/Desktop/backups/

echo -e "${Green}/etc/group and /etc/passwd files backed up."
echo -e "Backups folder created on the Desktop.${NC}"

clear
mkdir -p ~/Desktop/logs
chmod 777 ~/Desktop/logs
echo "Logs folder has been created on the Desktop."

clear
touch ~/Desktop/logs/allusers.txt
uidMin=$(grep "^UID_MIN" /etc/login.defs)
uidMax=$(grep "^UID_MAX" /etc/login.defs)
echo -e "User Accounts:" >> ~/Desktop/logs/allusers.txt
awk -F':' -v "min=${uidMin##UID_MIN}" -v "max=${uidMax##UID_MAX}" '{ if ( $3 >= min && $3 <= max  && $7 != "/sbin/nologin" ) print $0 }' /etc/passwd >> ~/Desktop/logs/allusers.txt
echo -e "\nSystem Accounts:" >> ~/Desktop/logs/allusers.txt
awk -F':' -v "min=${uidMin##UID_MIN}" -v "max=${uidMax##UID_MAX}" '{ if ( !($3 >= min && $3 <= max  && $7 != "/sbin/nologin")) print $0 }' /etc/passwd >> ~/Desktop/logs/allusers.txt
echo "All users have been logged."
cp /etc/services ~/Desktop/logs/allports.log
echo "All ports log has been created."
dpkg -l > ~/Desktop/logs/packages.log
echo "All packages log has been created."
apt-mark showmanual > ~/Desktop/logs/manuallyinstalled.log
echo "All manually instealled packages log has been created."
service --status-all > ~/Desktop/logs/allservices.txt
echo "All running services log has been created."
ps ax > ~/Desktop/logs/processes.log
echo "All running processes log has been created."
ss -l > ~/Desktop/logs/socketconnections.log
echo "All socket connections log has been created."
sudo netstat -tlnp > ~/Desktop/logs/listeningports.log
echo "All listening ports log has been created."
cp /var/log/auth.log ~/Desktop/logs/auth.log
echo "Auth log has been created."
cp /var/log/syslog ~/Desktop/logs/syslog.log
echo "System log has been created."

chmod 777 -R ~/Desktop/backups
chmod 777 -R ~/Desktop/logs

clear
chmod 777 /etc/apt/apt.conf.d/10periodic
cp /etc/apt/apt.conf.d/10periodic ~/Desktop/backups/
echo -e "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Download-Upgradeable-Packages \"1\";\nAPT::Periodic::AutocleanInterval \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";" > /etc/apt/apt.conf.d/10periodic
chmod 644 /etc/apt/apt.conf.d/10periodic
echo "Daily update checks, download upgradeable packages, autoclean interval, and unattended upgrade enabled."

clear
if [[ $(lsb_release -r) == "Release:	14.04" ]] || [[ $(lsb_release -r) == "Release:	14.10" ]]
then
	chmod 777 /etc/apt/sources.list
	cp /etc/apt/sources.list ~/Desktop/backups/
	echo -e "deb http://us.archive.ubuntu.com/ubuntu/ trusty main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ trusty-security main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ trusty-updates main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ trusty-proposed main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty-security main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty-updates main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty-proposed main restricted universe multiverse" > /etc/apt/sources.list
	chmod 644 /etc/apt/sources.list
elif [[ $(lsb_release -r) == "Release:	12.04" ]] || [[ $(lsb_release -r) == "Release:	12.10" ]]
then
	chmod 777 /etc/apt/sources.list
	cp /etc/apt/sources.list ~/Desktop/backups/
	echo -e "deb http://us.archive.ubuntu.com/ubuntu/ precise main restricted universe multiverse \ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise main restricted universe multiverse \ndeb http://us.archive.ubuntu.com/ubuntu/ precise-security main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ precise-updates main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ precise-proposed main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise-security main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise-updates main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise-proposed main restricted universe multiverse" > /etc/apt/sources.list
	chmod 644 /etc/apt/sources.list
elif [[ $(lsb_release -r) == "Release:	16.04" ]] || [[ $(lsb_release -r) == "Release:	16.10" ]]
then
	chmod 777 /etc/apt/sources.list
	cp /etc/apt/sources.list ~Desktop/backups/
	echo -e "deb http://us.archive.ubuntu.com/ubuntu/ xenial main restricted universe multiverse \ndeb-src http://us.archive.ubuntu.com/ubuntu/ xenial main restricted universe multiverse \ndeb http://us.archive.ubuntu.com/ubuntu/ xenial-security main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ xenial-updates main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ xenial-proposed main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ xenial-security main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ xenial-updates main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ xenial-proposed main restricted universe multiverse" > /etc/apt/sources.list
	chmod 644 /etc/apt/sources.list
elif [[ $(lsb_release -r) == "Release:	18.04" ]] || [[ $(lsb_release -r) == "Release:	18.10" ]]
then
	chmod 777 /etc/apt/sources.list
	cp /etc/apt/sources.list ~/Desktop/backups/
	echo -e "deb http://us.archive.ubuntu.com/ubuntu/ bionic main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ bionic main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ bionic-security main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ bionic-updates main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ bionic-proposed main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ bionic-security main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ bionic-updates main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ bionic-proposed main restricted universe multiverse\ndeb-src http://security.ubuntu.com/ubuntu/ bionic-proposed main restricted universe multiverse" > /etc/apt/sources.list
	chmod 644 /etc/apt/sources.list
else
	echo “Error, cannot detect OS version”
fi
echo "Apt Repositories have been added."

if [ $update_y = "y" ]
then
clear
apt-get -qq update
apt-get -qq upgrade
apt-get -qq dist-upgrade
echo "Ubuntu OS has checked for updates and has been upgraded."

clear
apt-get -y -qq update && apt-get -y -qq install linux-image-generic
apt-get -y -qq update && apt-get -y -qq install linux-headers-generic
echo "Kernel updates checked for and upgraded."

clear
apt-get -y -qq autoremove
apt-get -y -qq autoclean
apt-get -y -qq clean
echo "All unused packages have been removed."

clear
echo "Check to verify that all update settings are correct."
update-manager

clear
apt-get -y -qq update
apt-get -y -qq upgrade openssl libssl-dev
apt-cache policy openssl libssl-dev
echo "OpenSSL heart bleed bug has been fixed."

clear
env i='() { :;}; echo Your system is Bash vulnerable. See checklist for how to secure.' bash -c "echo Bash vulnerability test"
echo "Shellshock Bash vulnerability is secured."
fi
}

function roottest() {
  ROOT_UID=0

  if [ "$UID" -eq "$ROOT_UID" ]
  then
    echo -e "${Green}RootCheck Good${NC}"
  else
    echo -e "${Red}Run as Root!!${NC}"
    exit 1
  fi
}

function InternetTest() {
  if ping -q -c 1 -W 1 8.8.8.8 >/dev/null; then
    echo -e "${Green}Internet Test Success${NC}"
  else
    echo -e "${Red}Internet Connection Unavailable${NC}"
    exit 1
  fi
}

function CMDSTEST() {
      if [ $? -eq 0 ]; then
         echo -e $1 "${Green}Successful${NC}"
      else
         echo -e $1 "${Red}Failed${NC}"
      fi
    }

function userlock() {

clear
cp /etc/login.defs ~/Desktop/backups/
sed -i '160s/.*/PASS_MAX_DAYS\o01130/' /etc/login.defs
sed -i '161s/.*/PASS_MIN_DAYS\o0113/' /etc/login.defs
sed -i '162s/.*/PASS_WARN_AGE\o0117/' /etc/login.defs
echo "Password policies have been set with /etc/login.defs."

clear
apt-get install libpam-cracklib -y -qq
cp /etc/pam.d/common-auth ~/Desktop/backups/
cp /etc/pam.d/common-password ~/Desktop/backups/
#SET THIS TO WHAT WE HAVE
echo -e "#\n# /etc/pam.d/common-auth - authentication settings common to all services\n#\n# This file is included from other service-specific PAM config files,\n# and should contain a list of the authentication modules that define\n# the central authentication scheme for use on the system\n# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the\n# traditional Unix authentication mechanisms.\n#\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\nauth	[success=1 default=ignore]	pam_unix.so nullok_secure\n# here's the fallback if no module succeeds\nauth	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already;\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\nauth	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\nauth	optional			pam_cap.so \n# end of pam-auth-update config\nauth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail audit even_deny_root_account silent" > /etc/pam.d/common-auth
echo -e "#\n# /etc/pam.d/common-password - password-related modules common to all services\n#\n# This file is included from other service-specific PAM config files,\n# and should contain a list of modules that define the services to be\n# used to change user passwords.  The default is pam_unix.\n\n# Explanation of pam_unix options:\n#\n# The \"sha512\" option enables salted SHA512 passwords.  Without this option,\n# the default is Unix crypt.  Prior releases used the option \"md5\".\n#\n# The \"obscure\" option replaces the old \`OBSCURE_CHECKS_ENAB\' option in\n# login.defs.\n#\n# See the pam_unix manpage for other options.\n\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\npassword	[success=1 default=ignore]	pam_unix.so obscure sha512\n# here's the fallback if no module succeeds\npassword	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already;\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\npassword	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\npassword	optional	pam_gnome_keyring.so \n# end of pam-auth-update config" > /etc/pam.d/common-password
#sed -i '1s/^/password requisite pam_cracklib.so try_first_pass retry=3 difok=4 minlen=16 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1 maxrepeat=2 reject_username gecoscheck enforce_for_root\n/' /etc/pam.d/common-password
echo "If password policies are not correctly configured, try this for /etc/pam.d/common-password:\npassword requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\npassword requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root"
echo "Password policies have been set with /etc/pam.d."


touch ~/Desktop/Password.txt
echo -e "Use Custom Password or built-in?(y/n)"
read pwyn
if [ $pwyn == y ]
then
    echo "Password:  "
    read pw
    echo "$pw" > ~/Desktop/Password.txt
    echo "Password has been set as '$pw'."
else
    echo 'H=Fmcqz3M]}&rfC$F>b)' > ~/Desktop/Password.txt
    echo "Password has been set as 'H=Fmcqz3M]}&rfC$F>b)'."
fi

chmod 777 ~/Desktop/Password.txt
echo "Password file is on desktop. Copy password from the file."
declare -i numusers
declare -i numadminusers
declare -i numnewusers
declare -A users=()
declare -A adminusers=()
declare -A newusers=()
echo "How many users need to be added? ex: 5 "
echo -e "Use Custom Password or built-in?(y/n)"
echo "DONT FORGET TO INCLUDE THEM LATER"
read numnewusers
echo "How many non-admin users? ex: 5"
read numusers
echo "How many ADMIN users? ex: 5"
read numadminusers
echo "Want to remove every user you haven't mentioned? (y/n)"
read removeunknownusers
i=1
((numnewusers += 1))
while [[ $i -lt $numnewusers ]] ; do
     echo "enter name of user$i - "
     read newusers[$i]
     echo "newuser$i recorded as - ${newusers[$i]}  - "
    (( i += 1 ))
done
i=1
while [[ $i -lt $numnewusers ]] ; do
    newuser=${newusers[$i]}
    echo "newuser$i is $newuser "
    (( i += 1 ))
done
while [[ $i -lt $numnewusers ]] ; do
    if [ $pwyn == yes ]
    then
      echo -e "$pw\n$pw" | adduser ${newusers[${i}]}
      echo "${newusers[${i}]} has been given the password '$pw'."
    else
      echo -e 'H=Fmcqz3M]}&rfC$F>b)\nH=Fmcqz3M]}&rfC$F>b)' | adduser ${newusers[${i}]}
      echo "${newusers[${i}]} has been given the password 'H=Fmcqz3M]}&rfC$F>b)'."
    fi
    echo "A user account for ${newusers[${i}]} has been created."
    (( i += 1 ))
done
i=1
((numusers += 1))
((numadminusers += 1))
while [[ $i -lt $numusers ]] ; do
     echo "enter name of user$i - "
     read users[$i]
     echo "user$i recorded as - ${users[$i]}  - "
    (( i += 1 ))
done
i=1
while [[ $i -lt $numusers ]] ; do
    user=${users[$i]}
    echo "user$i is $user "
    (( i += 1 ))
done
i=1
echo "Correct? (y/n)"
read correct
if [ $correct != "y" ]
then
    while [[ $i -lt $numusers ]] ; do
    echo -e "${Green}Beginning processes for regular users ${NC}"
    gpasswd -d ${users[${i}]} sudo
    gpasswd -d ${users[${i}]} adm
    gpasswd -d ${users[${i}]} lpadmin
    gpasswd -d ${users[${i}]} sambashare
    gpasswd -d ${users[${i}]} root
    if [ $pwyn == yes ]
    then
      echo -e "$pw\n$pw" | passwd ${users[${i}]}
      echo "${users[${i}]} has been given the password '$pw'."
    else
      echo -e 'H=Fmcqz3M]}&rfC$F>b)\nH=Fmcqz3M]}&rfC$F>b)' | passwd ${users[${i}]}
      echo "${users[${i}]} has been given the password 'H=Fmcqz3M]}&rfC$F>b)'."
    fi
    passwd -x30 -n3 -w7 ${users[${i}]}
  done
else
    echo -e "${Red}Doing NOTHING for regular users${NC}"
    sleep 10
fi
while [[ $i -lt $numadminusers ]] ; do
     echo "enter name of user$i - "
     read adminusers[$i]
     echo "adminuser$i recorded as - ${adminusers[$i]}  - "
    (( i += 1 ))
done
i=1
while [[ $i -lt $numadminusers ]] ; do
    adminuser=${adminusers[$i]}
    echo "adminuser$i is $adminuser "
    (( i += 1 ))
done
while [[ $i -lt $numusers ]] ; do
  echo "Correct? (y/n)"
  read correct
  if [ $correct != "y" ]
  then
    echo -e "${Green}Beginning processes for  adminusers ${NC}"
    gpasswd -a ${adminusers[${i}]} sudo
    gpasswd -a ${adminusers[${i}]} adm
    gpasswd -a ${adminusers[${i}]} lpadmin
    gpasswd -a ${adminusers[${i}]} sambashare
    if [ $pwyn == yes ]
    then
      echo -e "$pw\n$pw" | passwd ${adminusers[${i}]}
      echo "${adminusers[${i}]} has been given the password '$pw'."
    else
      echo -e 'H=Fmcqz3M]}&rfC$F>b)\nH=Fmcqz3M]}&rfC$F>b)' | passwd ${adminusers[${i}]}
      echo "${adminusers[${i}]} has been given the password 'H=Fmcqz3M]}&rfC$F>b)'."
    fi
    passwd -x30 -n3 -w7 ${adminusers[${i}]}
  else
    echo -e "${Red}Doing NOTHING for adminusers${NC}"
    sleep 10
  fi
done

echo "Check for any user folders that do not belong to any users in /home/."
ls -a /home/ >> ~/Desktop/Script.log


echo "Check for any files for users that should not be administrators in /etc/sudoers.d."
ls -a /etc/sudoers.d >> ~/Desktop/Script.log


echo "Remove all instances of '!authenticate' and 'NOPASSWD' from /etc/sudoers."
cp /etc/sudoers ~/Desktop/backups/
gedit /etc/sudoers


unalias -a
echo "All aliases have been removed."


usermod -L root
echo "Root account has been locked. Use 'usermod -U root' to unlock it."

chmod 640 .bash_history
echo "Bash history file permissions set."


chmod 600 /etc/shadow
echo "File permissions on shadow have been set."


chmod 644 /etc/passwd
echo "File permissions on passwd have been set."

clear
echo -e "${Green} User Functions Complete! ${NC}"
sleep 10
}

function filelock() {
  echo "All audio files Listed below." >> ~/Desktop/Script.log
  find / -name "*.midi" -type f >> ~/Desktop/Script.log
	find / -name "*.mid" -type f >> ~/Desktop/Script.log
	find / -name "*.mod" -type f >> ~/Desktop/Script.log
	find / -name "*.mp3" -type f >> ~/Desktop/Script.log
	find / -name "*.mp2" -type f >> ~/Desktop/Script.log
	find / -name "*.mpa" -type f >> ~/Desktop/Script.log
	find / -name "*.m4a" -type f >> ~/Desktop/Script.log
	find / -name "*.abs" -type f >> ~/Desktop/Script.log
	find / -name "*.mpega" -type f >> ~/Desktop/Script.log
	find / -name "*.au" -type f >> ~/Desktop/Script.log
	find / -name "*.snd" -type f >> ~/Desktop/Script.log
	find / -name "*.wav" -type f >> ~/Desktop/Script.log
	find / -name "*.aiff" -type f >> ~/Desktop/Script.log
	find / -name "*.aif" -type f >> ~/Desktop/Script.log
	find / -name "*.sid" -type f >> ~/Desktop/Script.log
	find / -name "*.flac" -type f >> ~/Desktop/Script.log
	find / -name "*.ogg" -type f >> ~/Desktop/Script.log
	find / -name "*.aac" -type f >> ~/Desktop/Script.log
  echo "All media files Listed below." >> ~/Desktop/Script.log
  find / -name "*.mpeg" -type f >> ~/Desktop/Script.log
	find / -name "*.mpg" -type f >> ~/Desktop/Script.log
	find / -name "*.mpe" -type f >> ~/Desktop/Script.log
	find / -name "*.dl" -type f >> ~/Desktop/Script.log
	find / -name "*.movie" -type f >> ~/Desktop/Script.log
	find / -name "*.movi" -type f >> ~/Desktop/Script.log
	find / -name "*.mv" -type f >> ~/Desktop/Script.log
	find / -name "*.iff" -type f >> ~/Desktop/Script.log
	find / -name "*.anim5" -type f >> ~/Desktop/Script.log
	find / -name "*.anim3" -type f >> ~/Desktop/Script.log
	find / -name "*.anim7" -type f >> ~/Desktop/Script.log
	find / -name "*.avi" -type f >> ~/Desktop/Script.log
	find / -name "*.vfw" -type f >> ~/Desktop/Script.log
	find / -name "*.avx" -type f >> ~/Desktop/Script.log
	find / -name "*.fli" -type f >> ~/Desktop/Script.log
	find / -name "*.flc" -type f >> ~/Desktop/Script.log
	find / -name "*.mov" -type f >> ~/Desktop/Script.log
	find / -name "*.qt" -type f >> ~/Desktop/Script.log
	find / -name "*.spl" -type f >> ~/Desktop/Script.log
	find / -name "*.swf" -type f >> ~/Desktop/Script.log
	find / -name "*.dcr" -type f >> ~/Desktop/Script.log
	find / -name "*.dir" -type f >> ~/Desktop/Script.log
	find / -name "*.dxr" -type f >> ~/Desktop/Script.log
	find / -name "*.rpm" -type f >> ~/Desktop/Script.log
	find / -name "*.rm" -type f >> ~/Desktop/Script.log
	find / -name "*.smi" -type f >> ~/Desktop/Script.log
	find / -name "*.ra" -type f >> ~/Desktop/Script.log
	find / -name "*.ram" -type f >> ~/Desktop/Script.log
	find / -name "*.rv" -type f >> ~/Desktop/Script.log
	find / -name "*.wmv" -type f >> ~/Desktop/Script.log
	find / -name "*.asf" -type f >> ~/Desktop/Script.log
	find / -name "*.asx" -type f >> ~/Desktop/Script.log
	find / -name "*.wma" -type f >> ~/Desktop/Script.log
	find / -name "*.wax" -type f >> ~/Desktop/Script.log
	find / -name "*.wmv" -type f >> ~/Desktop/Script.log
	find / -name "*.wmx" -type f >> ~/Desktop/Script.log
	find / -name "*.3gp" -type f >> ~/Desktop/Script.log
	find / -name "*.mov" -type f >> ~/Desktop/Script.log
	find / -name "*.mp4" -type f >> ~/Desktop/Script.log
	find / -name "*.avi" -type f >> ~/Desktop/Script.log
	find / -name "*.swf" -type f >> ~/Desktop/Script.log
	find / -name "*.flv" -type f >> ~/Desktop/Script.log
	find / -name "*.m4v" -type f >> ~/Desktop/Script.log
  echo "All image files Listed below." >> ~/Desktop/Script.log
  find / -name "*.tiff" -type f >> ~/Desktop/Script.log
	find / -name "*.tif" -type f >> ~/Desktop/Script.log
	find / -name "*.rs" -type f >> ~/Desktop/Script.log
	find / -name "*.im1" -type f >> ~/Desktop/Script.log
	find / -name "*.gif" -type f >> ~/Desktop/Script.log
	find / -name "*.jpeg" -type f >> ~/Desktop/Script.log
	find / -name "*.jpg" -type f >> ~/Desktop/Script.log
	find / -name "*.jpe" -type f >> ~/Desktop/Script.log
	find / -name "*.png" -type f >> ~/Desktop/Script.log
	find / -name "*.rgb" -type f >> ~/Desktop/Script.log
	find / -name "*.xwd" -type f >> ~/Desktop/Script.log
	find / -name "*.xpm" -type f >> ~/Desktop/Script.log
	find / -name "*.ppm" -type f >> ~/Desktop/Script.log
	find / -name "*.pbm" -type f >> ~/Desktop/Script.log
	find / -name "*.pgm" -type f >> ~/Desktop/Script.log
	find / -name "*.pcx" -type f >> ~/Desktop/Script.log
	find / -name "*.ico" -type f >> ~/Desktop/Script.log
	find / -name "*.svg" -type f >> ~/Desktop/Script.log
	find / -name "*.svgz" -type f >> ~/Desktop/Script.log
	find / -name "*.bmp" -type f >> ~/Desktop/Script.log
	find / -name "*.img" -type f >> ~/Desktop/Script.log
  echo "All text and executable files Listed below." >> ~/Desktop/Script.log
  find / -name "*.txt" -type f >> ~/Desktop/Script.log
	find / -name "*.exe" -type f >> ~/Desktop/Script.log
	find / -name "*.msi" -type f >> ~/Desktop/Script.log
	find / -name "*.bat" -type f >> ~/Desktop/Script.log
	find / -name "*.sh" -type f >> ~/Desktop/Script.log
  echo "All startup scripts Listed below." >> ~/Desktop/Script.log
  cp /etc/rc.local ~/Desktop/backups/
  echo > /etc/rc.local
  echo 'exit 0' >> /etc/rc.local
  echo "Any startup scripts have been removed."
  echo "All bin scripts Listed below." >> ~/Desktop/Script.log
  find /bin/ -name "*.sh" -type f -delete
  echo "Scripts in bin have been removed."
  echo "files with permissions between 700 and 777 list below."
  ind / -type f -perm 777 >> ~/Desktop/Script.log
  find / -type f -perm 776 >> ~/Desktop/Script.log
  find / -type f -perm 775 >> ~/Desktop/Script.log
  find / -type f -perm 774 >> ~/Desktop/Script.log
  find / -type f -perm 773 >> ~/Desktop/Script.log
  find / -type f -perm 772 >> ~/Desktop/Script.log
  find / -type f -perm 771 >> ~/Desktop/Script.log
  find / -type f -perm 770 >> ~/Desktop/Script.log
  find / -type f -perm 767 >> ~/Desktop/Script.log
  find / -type f -perm 766 >> ~/Desktop/Script.log
  find / -type f -perm 765 >> ~/Desktop/Script.log
  find / -type f -perm 764 >> ~/Desktop/Script.log
  find / -type f -perm 763 >> ~/Desktop/Script.log
  find / -type f -perm 762 >> ~/Desktop/Script.log
  find / -type f -perm 761 >> ~/Desktop/Script.log
  find / -type f -perm 760 >> ~/Desktop/Script.log
  find / -type f -perm 757 >> ~/Desktop/Script.log
  find / -type f -perm 756 >> ~/Desktop/Script.log
  find / -type f -perm 755 >> ~/Desktop/Script.log
  find / -type f -perm 754 >> ~/Desktop/Script.log
  find / -type f -perm 753 >> ~/Desktop/Script.log
  find / -type f -perm 752 >> ~/Desktop/Script.log
  find / -type f -perm 751 >> ~/Desktop/Script.log
  find / -type f -perm 750 >> ~/Desktop/Script.log
  find / -type f -perm 747 >> ~/Desktop/Script.log
  find / -type f -perm 746 >> ~/Desktop/Script.log
  find / -type f -perm 745 >> ~/Desktop/Script.log
  find / -type f -perm 744 >> ~/Desktop/Script.log
  find / -type f -perm 743 >> ~/Desktop/Script.log
  find / -type f -perm 742 >> ~/Desktop/Script.log
  find / -type f -perm 741 >> ~/Desktop/Script.log
  find / -type f -perm 740 >> ~/Desktop/Script.log
  find / -type f -perm 737 >> ~/Desktop/Script.log
  find / -type f -perm 736 >> ~/Desktop/Script.log
  find / -type f -perm 735 >> ~/Desktop/Script.log
  find / -type f -perm 734 >> ~/Desktop/Script.log
  find / -type f -perm 733 >> ~/Desktop/Script.log
  find / -type f -perm 732 >> ~/Desktop/Script.log
  find / -type f -perm 731 >> ~/Desktop/Script.log
  find / -type f -perm 730 >> ~/Desktop/Script.log
  find / -type f -perm 727 >> ~/Desktop/Script.log
  find / -type f -perm 726 >> ~/Desktop/Script.log
  find / -type f -perm 725 >> ~/Desktop/Script.log
  find / -type f -perm 724 >> ~/Desktop/Script.log
  find / -type f -perm 723 >> ~/Desktop/Script.log
  find / -type f -perm 722 >> ~/Desktop/Script.log
  find / -type f -perm 721 >> ~/Desktop/Script.log
  find / -type f -perm 720 >> ~/Desktop/Script.log
  find / -type f -perm 717 >> ~/Desktop/Script.log
  find / -type f -perm 716 >> ~/Desktop/Script.log
  find / -type f -perm 715 >> ~/Desktop/Script.log
  find / -type f -perm 714 >> ~/Desktop/Script.log
  find / -type f -perm 713 >> ~/Desktop/Script.log
  find / -type f -perm 712 >> ~/Desktop/Script.log
  find / -type f -perm 711 >> ~/Desktop/Script.log
  find / -type f -perm 710 >> ~/Desktop/Script.log
  find / -type f -perm 707 >> ~/Desktop/Script.log
  find / -type f -perm 706 >> ~/Desktop/Script.log
  find / -type f -perm 705 >> ~/Desktop/Script.log
  find / -type f -perm 704 >> ~/Desktop/Script.log
  find / -type f -perm 703 >> ~/Desktop/Script.log
  find / -type f -perm 702 >> ~/Desktop/Script.log
  find / -type f -perm 701 >> ~/Desktop/Script.log
  find / -type f -perm 700 >> ~/Desktop/Script.log
  echo "All files with file permissions between 700 and 777 have been listed above."
  echo "PHP files listed below."
  ind / -name "*.php" -type f >> ~/Desktop/Script.log
  echo "All PHP files have been listed above. ('/var/cache/dictionaries-common/sqspell.php' is a system PHP file)"

  clear
  crontab -l > ~/Desktop/backups/crontab-old
  crontab -r
  echo "Crontab has been backed up. All startup tasks have been removed from crontab."

  clear
  cd /etc/
  /bin/rm -f cron.deny at.deny
  echo root >cron.allow
  echo root >at.allow
  /bin/chown root:root cron.allow at.allow
  /bin/chmod 400 cron.allow at.allow
  cd ..
  echo "Only root allowed in cron."


}

function applock() {
  echo -e "${Green}Applock starting${NC}"
	if [ $sambaYN == no ]
	then
		ufw deny netbios-ns
		ufw deny netbios-dgm
		ufw deny netbios-ssn
		ufw deny microsoft-ds
		apt-get purge samba -y -qq
		apt-get purge samba-common -y  -qq
		apt-get purge samba-common-bin -y -qq
		apt-get purge samba4 -y -qq
		clear
		echo "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been denied. Samba has been removed."
	elif [ $sambaYN == yes ]
	then
		ufw allow netbios-ns
		ufw allow netbios-dgm
		ufw allow netbios-ssn
		ufw allow microsoft-ds
		apt-get install samba -y -qq
		apt-get install system-config-samba -y -qq
		cp /etc/samba/smb.conf ~/Desktop/backups/
		if [ "$(grep '####### Authentication #######' /etc/samba/smb.conf)"==0 ]
		then
			sed -i 's/####### Authentication #######/####### Authentication #######\nsecurity = user/g' /etc/samba/smb.conf
		fi
		sed -i 's/usershare allow guests = no/usershare allow guests = yes/g' /etc/samba/smb.conf

		echo Type all user account names, with a space in between
		read -a usersSMB
		usersSMBLength=${#usersSMB[@]}
		for (( i=0;i<$usersSMBLength;i++))
		do
			echo -e 'H=Fmcqz3M]}&rfC$F>b)\nH=Fmcqz3M]}&rfC$F>b)' | smbpasswd -a ${usersSMB[${i}]}
			echo "${usersSMB[${i}]} has been given the password 'H=Fmcqz3M]}&rfC$F>b)' for Samba."
		done
		echo "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been denied. Samba config file has been configured."
		clear
	else
		echo Response not recognized.
	fi
	echo "Samba is complete."

	clear
	if [ $ftpYN == no ]
	then
		ufw deny ftp
		ufw deny sftp
		ufw deny saft
		ufw deny ftps-data
		ufw deny ftps
		apt-get purge vsftpd -y -qq
		echo "vsFTPd has been removed. ftp, sftp, saft, ftps-data, and ftps ports have been denied on the firewall."
	elif [ $ftpYN == yes ]
	then
		ufw allow ftp
		ufw allow sftp
		ufw allow saft
		ufw allow ftps-data
		ufw allow ftps
		cp /etc/vsftpd/vsftpd.conf ~/Desktop/backups/
		cp /etc/vsftpd.conf ~/Desktop/backups/
		gedit /etc/vsftpd/vsftpd.conf&gedit /etc/vsftpd.conf
		service vsftpd restart
		echo "ftp, sftp, saft, ftps-data, and ftps ports have been allowed on the firewall. vsFTPd service has been restarted."
	else
		echo Response not recognized.
	fi
	echo "FTP is complete."


	clear
	if [ $sshYN == no ]
	then
		ufw deny ssh
		apt-get purge openssh-server -y -qq
		echo "SSH port has been denied on the firewall. Open-SSH has been removed."
	elif [ $sshYN == yes ]
	then
		apt-get install openssh-server -y -qq
		apt-get install libpam-google-authenticator -y -qq
		ufw allow ssh
		cp /etc/ssh/sshd_config ~/Desktop/backups/
		echo Type all user account names, with a space in between
		read usersSSH
		echo -e "# Package generated configuration file\n# See the sshd_config(5) manpage for details\n\n# What ports, IPs and protocols we listen for\nPort 3784\n# Use these options to restrict which interfaces/protocols sshd will bind to\n#ListenAddress ::\n#ListenAddress 0.0.0.0\nProtocol 2\n# HostKeys for protocol version \nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_dsa_key\nHostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n#Privilege Separation is turned on for security\nUsePrivilegeSeparation yes\n\n# Lifetime and size of ephemeral version 1 server key\nKeyRegenerationInterval 3600\nServerKeyBits 1024\n\n# Logging\nSyslogFacility AUTH\nLogLevel VERBOSE\n\n# Authentication:\nLoginGraceTime 60\nPermitRootLogin no\nStrictModes yes\n\nRSAAuthentication yes\nPubkeyAuthentication yes\n#AuthorizedKeysFile	%h/.ssh/authorized_keys\n\n# Don't read the user's ~/.rhosts and ~/.shosts files\nIgnoreRhosts yes\n# For this to work you will also need host keys in /etc/ssh_known_hosts\nRhostsRSAAuthentication no\n# similar for protocol version 2\nHostbasedAuthentication no\n# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication\n#IgnoreUserKnownHosts yes\n\n# To enable empty passwords, change to yes (NOT RECOMMENDED)\nPermitEmptyPasswords no\n\n# Change to yes to enable challenge-response passwords (beware issues with\n# some PAM modules and threads)\nChallengeResponseAuthentication yes\n\n# Change to no to disable tunnelled clear text passwords\nPasswordAuthentication no\n\n# Kerberos options\n#KerberosAuthentication no\n#KerberosGetAFSToken no\n#KerberosOrLocalPasswd yes\n#KerberosTicketCleanup yes\n\n# GSSAPI options\n#GSSAPIAuthentication no\n#GSSAPICleanupCredentials yes\n\nX11Forwarding no\nX11DisplayOffset 10\nPrintMotd no\nPrintLastLog no\nTCPKeepAlive yes\n#UseLogin no\n\nMaxStartups 2\n#Banner /etc/issue.net\n\n# Allow client to pass locale environment variables\nAcceptEnv LANG LC_*\n\nSubsystem sftp /usr/lib/openssh/sftp-server\n\n# Set this to 'yes' to enable PAM authentication, account processing,\n# and session processing. If this is enabled, PAM authentication will\n# be allowed through the ChallengeResponseAuthentication and\n# PasswordAuthentication.  Depending on your PAM configuration,\n# PAM authentication via ChallengeResponseAuthentication may bypass\n# the setting of \"PermitRootLogin without-password\".\n# If you just want the PAM account and session checks to run without\n# PAM authentication, then enable this but set PasswordAuthentication\n# and ChallengeResponseAuthentication to 'no'.\nUsePAM yes\n\nAllowUsers $usersSSH\nDenyUsers\nRhostsAuthentication no\nClientAliveInterval 300\nClientAliveCountMax 0\nVerifyReverseMapping yes\nAllowTcpForwarding no\nUseDNS no\nPermitUserEnvironment no" > /etc/ssh/sshd_config
		service ssh restart
		mkdir ~/.ssh
		chmod 700 ~/.ssh
		ssh-keygen -t rsa
		echo "SSH port has been allowed on the firewall. SSH config file has been configured. SSH RSA 2048 keys have been created."
	else
		echo Response not recognized.
	fi
	echo "SSH is complete."

	clear
	if [ $telnetYN == no ]
	then
		ufw deny telnet
		ufw deny rtelnet
		ufw deny telnets
		apt-get purge telnet -y -qq
		apt-get purge telnetd -y -qq
		apt-get purge inetutils-telnetd -y -qq
		apt-get purge telnetd-ssl -y -qq
		echo "Telnet port has been denied on the firewall and Telnet has been removed."
	elif [ $telnetYN == yes ]
	then
		ufw allow telnet
		ufw allow rtelnet
		ufw allow telnets
		echo "Telnet port has been allowed on the firewall."
	else
		echo Response not recognized.
	fi
	echo "Telnet is complete."



	clear
	if [ $mailYN == no ]
	then
		ufw deny smtp
		ufw deny pop2
		ufw deny pop3
		ufw deny imap2
		ufw deny imaps
		ufw deny pop3s
		echo "smtp, pop2, pop3, imap2, imaps, and pop3s ports have been denied on the firewall."
	elif [ $mailYN == yes ]
	then
		ufw allow smtp
		ufw allow pop2
		ufw allow pop3
		ufw allow imap2
		ufw allow imaps
		ufw allow pop3s
		echo "smtp, pop2, pop3, imap2, imaps, and pop3s ports have been allowed on the firewall."
	else
		echo Response not recognized.
	fi
	echo "Mail is complete."



	clear
	if [ $printYN == no ]
	then
		ufw deny ipp
		ufw deny printer
		ufw deny cups
		echo "ipp, printer, and cups ports have been denied on the firewall."
	elif [ $printYN == yes ]
	then
		ufw allow ipp
		ufw allow printer
		ufw allow cups
		echo "ipp, printer, and cups ports have been allowed on the firewall."
	else
		echo Response not recognized.
	fi
	echo "Printing is complete."



	clear
	if [ $dbYN == no ]
	then
		ufw deny ms-sql-s
		ufw deny ms-sql-m
		ufw deny mysql
		ufw deny mysql-proxy
		apt-get purge mysql -y -qq
		apt-get purge mysql-client-core-5.5 -y -qq
		apt-get purge mysql-client-core-5.6 -y -qq
		apt-get purge mysql-common-5.5 -y -qq
		apt-get purge mysql-common-5.6 -y -qq
		apt-get purge mysql-server -y -qq
		apt-get purge mysql-server-5.5 -y -qq
		apt-get purge mysql-server-5.6 -y -qq
		apt-get purge mysql-client-5.5 -y -qq
		apt-get purge mysql-client-5.6 -y -qq
		apt-get purge mysql-server-core-5.6 -y -qq
		echo "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been denied on the firewall. MySQL has been removed."
	elif [ $dbYN == yes ]
	then
		ufw allow ms-sql-s
		ufw allow ms-sql-m
		ufw allow mysql
		ufw allow mysql-proxy
		apt-get install mysql-server-5.6 -y -qq
		cp /etc/my.cnf ~/Desktop/backups/
		cp /etc/mysql/my.cnf ~/Desktop/backups/
		cp /usr/etc/my.cnf ~/Desktop/backups/
		cp ~/.my.cnf ~/Desktop/backups/
		if grep -q "bind-address" "/etc/mysql/my.cnf"
		then
			sed -i "s/bind-address\t\t=.*/bind-address\t\t= 127.0.0.1/g" /etc/mysql/my.cnf
		fi
		gedit /etc/my.cnf&gedit /etc/mysql/my.cnf&gedit /usr/etc/my.cnf&gedit ~/.my.cnf
		service mysql restart
		echo "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been allowed on the firewall. MySQL has been installed. MySQL config file has been secured. MySQL service has been restarted."
	else
		echo Response not recognized.
	fi
	echo "MySQL is complete."



	clear
	if [ $httpYN == no ]
	then
		ufw deny http
		ufw deny https
		apt-get purge apache2 -y -qq
		rm -r /var/www/*
		echo "http and https ports have been denied on the firewall. Apache2 has been removed. Web server files have been removed."
	elif [ $httpYN == yes ]
	then
		apt-get install apache2 -y -qq
		ufw allow http
		ufw allow https
		cp /etc/apache2/apache2.conf ~/Desktop/backups/
		if [ -e /etc/apache2/apache2.conf ]
		then
	  	  echo -e '\<Directory \>\n\t AllowOverride None\n\t Order Deny,Allow\n\t Deny from all\n\<Directory \/\>\nUserDir disabled root' >> /etc/apache2/apache2.conf
		fi
		chown -R root:root /etc/apache2

		echo "http and https ports have been allowed on the firewall. Apache2 config file has been configured. Only root can now access the Apache2 folder."
	else
		echo Response not recognized.
	fi
	echo "Web Server is complete."



	clear
	if [ $dnsYN == no ]
	then
		ufw deny domain
		apt-get purge bind9 -qq
		echo "domain port has been denied on the firewall. DNS name binding has been removed."
	elif [ $dnsYN == yes ]
	then
		ufw allow domain
		echo "domain port has been allowed on the firewall."
	else
		echo Response not recognized.
	fi
	echo "DNS is complete."

	clear
	apt-get purge netcat -y -qq
	apt-get purge netcat-openbsd -y -qq
	apt-get purge netcat-traditional -y -qq
	apt-get purge ncat -y -qq
	apt-get purge pnetcat -y -qq
	apt-get purge socat -y -qq
	apt-get purge sock -y -qq
	apt-get purge socket -y -qq
	apt-get purge sbd -y -qq
	rm /usr/bin/nc
	clear
	echo "Netcat and all other instances have been removed."

	apt-get purge john -y -qq
	apt-get purge john-data -y -qq
	clear
	echo "John the Ripper has been removed."

	apt-get purge hydra -y -qq
	apt-get purge hydra-gtk -y -qq
	clear
	echo "Hydra has been removed."

	apt-get purge aircrack-ng -y -qq
	clear
	echo "Aircrack-NG has been removed."

	apt-get purge fcrackzip -y -qq
	clear
	echo "FCrackZIP has been removed."

	apt-get purge lcrack -y -qq
	clear
	echo "LCrack has been removed."

	apt-get purge ophcrack -y -qq
	apt-get purge ophcrack-cli -y -qq
	clear
	echo "OphCrack has been removed."

	apt-get purge pdfcrack -y -qq
	clear
	echo "PDFCrack has been removed."

	apt-get purge pyrit -y -qq
	clear
	echo "Pyrit has been removed."

	apt-get purge rarcrack -y -qq
	clear
	echo "RARCrack has been removed."

	apt-get purge sipcrack -y -qq
	clear
	echo "SipCrack has been removed."

	apt-get purge irpas -y -qq
	clear
	echo "IRPAS has been removed."

	clear
	echo 'Are there any hacking tools shown? (not counting libcrack2:amd64 or cracklib-runtime)'
	dpkg -l | egrep "crack|hack" >> ~/Desktop/Script.log

	apt-get purge logkeys -y -qq
	clear
	echo "LogKeys has been removed."

	apt-get purge zeitgeist-core -y -qq
	apt-get purge zeitgeist-datahub -y -qq
	apt-get purge python-zeitgeist -y -qq
	apt-get purge rhythmbox-plugin-zeitgeist -y -qq
	apt-get purge zeitgeist -y -qq
	echo "Zeitgeist has been removed."

	apt-get purge nfs-kernel-server -y -qq
	apt-get purge nfs-common -y -qq
	apt-get purge portmap -y -qq
	apt-get purge rpcbind -y -qq
	apt-get purge autofs -y -qq
	echo "NFS has been removed."

	apt-get purge nginx -y -qq
	apt-get purge nginx-common -y -qq
	echo "NGINX has been removed."

	apt-get purge inetd -y -qq
	apt-get purge openbsd-inetd -y -qq
	apt-get purge xinetd -y -qq
	apt-get purge inetutils-ftp -y -qq
	apt-get purge inetutils-ftpd -y -qq
	apt-get purge inetutils-inetd -y -qq
	apt-get purge inetutils-ping -y -qq
	apt-get purge inetutils-syslogd -y -qq
	apt-get purge inetutils-talk -y -qq
	apt-get purge inetutils-talkd -y -qq
	apt-get purge inetutils-telnet -y -qq
	apt-get purge inetutils-telnetd -y -qq
	apt-get purge inetutils-tools -y -qq
	apt-get purge inetutils-traceroute -y -qq
	echo "Inetd (super-server) and all inet utilities have been removed."

	clear
	apt-get purge vnc4server -y -qq
	apt-get purge vncsnapshot -y -qq
	apt-get purge vtgrab -y -qq
	echo "VNC has been removed."

	clear
	apt-get purge snmp -y -qq
	echo "SNMP has been removed."

	clear
	apt-get purge zenmap -y -qq
	apt-get purge nmap -y -qq
	echo "Zenmap and nmap have been removed."

	clear
	apt-get purge wireshark -y -qq
	apt-get purge wireshark-common -y -qq
	apt-get purge wireshark-gtk -y -qq
	apt-get purge wireshark-qt -y -qq
	echo "Wireshark has been removed."

	clear
	apt-get purge crack -y -qq
	apt-get purge crack-common -y -qq
	echo "Crack has been removed."

	clear
	apt-get purge medusa -y -qq
	echo "Medusa has been removed."

	clear
	apt-get purge nikto -y -qq
	echo "Nikto has been removed."

	clear
	apt-get purge _ -y -qq #WorldForge
	echo "WorldForge has been removed."

	clear
	apt-get purge _ -y -qq #Minetest
	echo "Minetest has been removed."

	clear
	apt-get purge _ -y -qq #Freeciv
	echo "Freeciv has been removed."

	clear
	apt-get purge _ -y -qq #Aisleriot
	echo "Aisleriot has been removed."

	clear
	apt-get purge _ -y -qq #Wesnoth
	echo "Wesnoth has been removed."

	clear
	apt-get install firefox hardinfo chkrootkit portsentry lynis gufw sysv-rc-conf nessus clamav rkhunter -y -qq
	apt-get install --reinstall coreutils -y -qq
	echo "Firefox, hardinfo, chkrootkit, portsentry, lynis, gufw, sysv-rc-conf, nessus, clamav, and rkhunter installed."

	clear
	apt-get install apparmor apparmor-profiles apparmor-utils -y -qq #check?
	echo "AppArmor has been installed."
}

function netlock(){
  echo -e "${Green}Netlock starting${NC}"
	#this is a later problem, add what you want
}


#put fullsend last, just calls others
function fullsend() {
  echo -e "${Green} Full send - I'm not responsible if this screws something up. ${NC}"
  if [ "$1" = "Full"]
  then
  roottest
  InternetTest
  filelock
  userlock
  applock
  netlock
fi
}

exit 0
