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

function antt_addUser() {
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

function antt_tunUp()
{
      cat << EOF > /etc/network/if-up.d/tun-up
#!/usr/bin/env bash
user_list=(\$(who | grep -E "\(:[0-9](\.[0-9])*\)" | awk '{print \$1 "@" \$NF}' | sort -u))
for user in \$user_list; do
username=\${user%@*}
su \$username -c 'notify-send "Canh bao" "Ban dang ket noi VPN vao he thong TCBS toan bo thong tin ket noi cua ban se deu duoc ghi log" -u critical -t 10000 -i /usr/share/hplip/data/images/32x32/warning.png'
done
EOF
}

function antt_umask()
{
    if [ -f /etc/init.d/rc ]; then
    sed -i 's/umask 022/umask 077/g' /etc/init.d/rc
  fi

  if ! grep -q -i "umask" "/etc/profile" 2> /dev/null; then
    echo "umask 077" >> /etc/profile
  fi

  if ! grep -q -i "umask" "/etc/bash.bashrc" 2> /dev/null; then
    echo "umask 077" >> /etc/bash.bashrc
  fi

  if ! grep -q -i "TMOUT" "/etc/profile.d/*" 2> /dev/null; then
    echo -e 'TMOUT=600\nreadonly TMOUT\nexport TMOUT' > '/etc/profile.d/autologout.sh'
    chmod +x /etc/profile.d/autologout.sh
  fi
}

function antt_removeUserNotNeed()
{
  for users in games gnats irc list news sync uucp; do
    userdel -r "$users" 2> /dev/null
  done
}

function antt_rhost()
{
    while read -r hostpasswd; do
    find "$hostpasswd" \( -name "hosts.equiv" -o -name ".rhosts" \) -exec rm -f {} \; 2> /dev/null

    if [[ $VERBOSE == "Y" ]]; then
      echo "$hostpasswd"
    fi

  done <<< "$(awk -F ":" '{print $6}' /etc/passwd)"

  if [[ -f /etc/hosts.equiv ]]; then
    rm /etc/hosts.equiv
  fi
}

function antt_dismod()
{
    local MOD
  MOD="bluetooth bnep btusb cpia2 firewire-core floppy n_hdlc net-pf-31 pcspkr soundcore thunderbolt usb-midi usb-storage uvcvideo v4l2_common"
  for disable in $MOD; do
    if ! grep -q "$disable" "$DISABLEMOD" 2> /dev/null; then
      echo "install $disable /bin/true" >> "$DISABLEMOD"
    fi
  done
}

function antt_DisInstallDpkg()
{
    if ! grep 'mount.* /tmp' /etc/apt/apt.conf.d/* ; then
    echo 'DPkg::Pre-Invoke {"mount -o remount,exec,nodev,nosuid /tmp";};' >> /etc/apt/apt.conf.d/99noexec-tmp
    echo 'DPkg::Post-Invoke {"mount -o remount,mode=1777,strictatime,noexec,nodev,nosuid /tmp";};' >> /etc/apt/apt.conf.d/99noexec-tmp
  fi
}
function antt_safemod()
{
  sed -i 's/DIR_MODE=.*/DIR_MODE=0750/' "$ADDUSER"
  sed -i 's/DSHELL=.*/DSHELL=\/bin\/false/' "$ADDUSER"
  sed -i 's/USERGROUPS=.*/USERGROUPS=yes/' "$ADDUSER"

  sed -i 's/SHELL=.*/SHELL=\/bin\/false/' "$USERADD"
  sed -i 's/^# INACTIVE=.*/INACTIVE=30/' "$USERADD"

  awk -F ':' '{if($3 >= 1000 && $3 <= 65000) print $6}' /etc/passwd | while read -r userhome; do
    chmod 0750 "$userhome"
  done

}
function antt_host()
{
  echo "sshd : ALL : ALLOW" > /etc/hosts.allow
  echo "ALL: LOCAL, 127.0.0.1" >> /etc/hosts.allow
  echo "ALL: ALL" > /etc/hosts.deny
  chmod 644 /etc/hosts.allow
  chmod 644 /etc/hosts.deny
}
## Run Function

antt_addUser
antt_tunUp
antt_umask
antt_removeUserNotNeed
antt_rhost
antt_dismod
antt_DisInstallDpkg
antt_safemod
antt_host

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
