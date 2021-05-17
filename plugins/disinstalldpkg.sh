!#/bin/bash
    if ! grep 'mount.* /tmp' /etc/apt/apt.conf.d/* ; then
    echo 'DPkg::Pre-Invoke {"mount -o remount,exec,nodev,nosuid /tmp";};' >> /etc/apt/apt.conf.d/99noexec-tmp
    echo 'DPkg::Post-Invoke {"mount -o remount,mode=1777,strictatime,noexec,nodev,nosuid /tmp";};' >> /etc/apt/apt.conf.d/99noexec-tmp
  fi