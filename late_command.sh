#!/bin/bash

# This script will run once after a fresh installation

# todo
# clear terminal from wrapped lines

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

# Sync and reboot
sync
sleep 3
reboot
