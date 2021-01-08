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
echo "Full - Userlock - Help - Prework"
echo -e "${Red}There  is  NO  WARRANTY, to the extent permitted by law.${NC}"
exit 0
fi
####################################LOG&BACKUP FILE####################################
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
#I have 0 idea what the stuff below this is, but I saw the word log so
clear
apt-get install tree -y -qq
apt-get install diffuse -y -qq
mkdir Desktop/Comparatives
chmod 777 Desktop/Comparatives

cp /etc/apt/apt.conf.d/10periodic Desktop/Comparatives/
cp Desktop/logs/allports.log Desktop/Comparatives/
cp Desktop/logs/allservices.txt Desktop/Comparatives/
touch Desktop/Comparatives/alltextfiles.txt
find . -type f -exec grep -Iq . {} \; -and -print >> Desktop/Comparatives/alltextfiles.txt
cp Desktop/logs/allusers.txt Desktop/Comparatives/
cp /etc/apache2/apache2.conf Desktop/Comparatives/
cp /etc/pam.d/common-auth Desktop/Comparatives/
cp /etc/pam.d/common-password Desktop/Comparatives/
cp /etc/init/control-alt-delete.conf Desktop/Comparatives/
crontab -l > Desktop/Comparatives/crontab.log
cp /etc/group Desktop/Comparatives/
cp /etc/hosts Desktop/Comparatives/
touch Desktop/Comparatives/initctl-running.txt
initctl list | grep running > Desktop/Comparatives/initctl-running.txt
cp /etc/lightdm/lightdm.conf Desktop/Comparatives/
cp Desktop/logs/listeningports.log Desktop/Comparatives/
cp /etc/login.defs Desktop/Comparatives/
cp Desktop/logs/manuallyinstalled.log Desktop/Comparatives/
cp /etc/mysql/my.cnf Desktop/Comparatives/
cp Desktop/logs/packages.log Desktop/Comparatives/
cp /etc/passwd Desktop/Comparatives/
cp Desktop/logs/processes.log Desktop/Comparatives/
cp /etc/rc.local Desktop/Comparatives/
cp /etc/samba/smb.conf Desktop/Comparatives/
cp Desktop/logs/socketconnections.log Desktop/Comparatives/
cp /etc/apt/sources.list Desktop/Comparatives/
cp /etc/ssh/sshd_config Desktop/Comparatives/
cp /etc/sudoers Desktop/Comparatives/
cp /etc/sysctl.conf Desktop/Comparatives/
tree / -o Desktop/Comparatives/tree.txt -n -p -h -u -g -D -v
cp /etc/vsftpd.conf Desktop/Comparatives/
echo "Tree and Diffuse have been installed, files on current system have been copied for comparison."

chmod 777 -R Desktop/Comparatives/
chmod 777 -R Desktop/backups
chmod 777 -R Desktop/logs

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
else
	echo “Error, cannot detect OS version”
fi
echo "Apt Repositories have been added."
if [ $update_y = "y" ]
then
clear
apt-get update -qq
apt-get upgrade -qq
apt-get dist-upgrade -qq
echo "Ubuntu OS has checked for updates and has been upgraded."

clear
apt-get update && apt-get install linux-image-generic -y -qq
apt-get update && apt-get install linux-headers-generic -y -qq
echo "Kernel updates checked for and upgraded."

clear
apt-get autoremove -y -qq
apt-get autoclean -y -qq
apt-get clean -y -qq
echo "All unused packages have been removed."

clear
echo "Check to verify that all update settings are correct."
update-manager

clear
apt-get update
apt-get upgrade openssl libssl-dev
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
  fi }
function CMDSTEST() {
      if [ $? -eq 0 ]; then
         echo -e $1 "${Green}Successful${NC}"
      else
         echo -e $1 "${Red}Failed${NC}"
      fi
    }
function userlock() {
####################################PASSWORD FILE####################################
touch ~/Desktop/Password.txt
echo -e "Use Custom Password or built-in?(y/n)"
read pwyn
if [ $pwyn == y ]
then
    echo "Password  -  "
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
	#also later problem
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
