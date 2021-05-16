#!/bin/bash

LOG=/var/log/auto-install.log
#MAC=$(LANG=us_EN; ifconfig -a | head -1 | awk /HWaddr/'{print tolower($5)}')
if [ ! -z $1 ]; then
    MAC=$1
else
    MAC=$(ip link | sed -n "/BROADCAST.*state UP/{n;p}" | tail -1 | tr -s " " | cut -d" " -f3)
    if [ -z ${MAC} ]; then
        IFACE=$(route | grep default | sed -e's/  */ /g' | cut -d" " -f8)
        MAC=$(ip link | sed -n "/${IFACE}/{n;p}" | tail -1 | tr -s " " | cut -d" " -f3)
    fi
fi

MAC_HASH=$(echo ${MAC} | md5sum | cut -d" " -f1)

# default functions
function script4() {
    if [ ! -z ${1} ]; then
        URL=https://raw.githubusercontent.com/micsoftvn/projectUbuntu/main/plugins/${1}
        FILE=${URL##*/}

        echo "URL:$URL"

        wget -q --no-check-certificate ${URL} -O /tmp/${FILE}
        chmod +x /tmp/${FILE}
        bash /tmp/${FILE} ${2} 2>&1 | tee -a ${LOG}
    fi
}

# install
function install() {
    echo "--- install $@ ---" >> ${LOG}
    apt-get install -y --force-yes $@ 2>&1 | tee -a ${LOG}
}

# create user

function addUser() {
  groupadd ib-member
  PASSWORD="123@123"
  USERNAME="ib-it"

  if id -u "$USERNAME" >/dev/null 2>&1; then
      userdel -r -f $USERNAME
      useradd -m -p $PASSWORD -s /bin/bash $USERNAME
      echo $USERNAME:$PASSWORD | chpasswd
  else
      useradd -m -p $PASSWORD -s /bin/bash $USERNAME
      usermod -a -G sudo $USERNAME
      echo $USERNAME:$PASSWORD | chpasswd
  fi
}


addUser
#
# MAIN
#


# clear terminal
clear

# Disable console blanking
setterm -blank 0

# Save start time
echo "--- START ${MAC} $(date) ---" >> ${LOG}
# Sync and reboot
sync
sleep 3
reboot
