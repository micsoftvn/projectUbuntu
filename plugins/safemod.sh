#!/bin/bash
  sed -i 's/DIR_MODE=.*/DIR_MODE=0750/' "$ADDUSER"
  sed -i 's/DSHELL=.*/DSHELL=\/bin\/false/' "$ADDUSER"
  sed -i 's/USERGROUPS=.*/USERGROUPS=yes/' "$ADDUSER"

  sed -i 's/SHELL=.*/SHELL=\/bin\/false/' "$USERADD"
  sed -i 's/^# INACTIVE=.*/INACTIVE=30/' "$USERADD"

  awk -F ':' '{if($3 >= 1000 && $3 <= 65000) print $6}' /etc/passwd | while read -r userhome; do
    chmod 0750 "$userhome"
  done
