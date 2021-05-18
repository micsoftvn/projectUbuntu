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
function antt_proxy()
{
  # Edit file Gnome
  cat << EOF > /usr/share/glib-2.0/schemas/org.gnome.system.proxy.gschema.xml
<?xml version="1.0" encoding="UTF-8"?>
<schemalist gettext-domain="gsettings-desktop-schemas">
  <schema id="org.gnome.system.proxy" path="/system/proxy/">
    <child name="http" schema="org.gnome.system.proxy.http"/>
    <child name="https" schema="org.gnome.system.proxy.https"/>
    <child name="ftp" schema="org.gnome.system.proxy.ftp"/>
    <child name="socks" schema="org.gnome.system.proxy.socks"/>
    <key name="mode" enum="org.gnome.desktop.GDesktopProxyMode">
      <default>'manual'</default>
      <summary>Proxy configuration mode</summary>
      <description>
        Select the proxy configuration mode. Supported values are “none”,
        “manual”, “auto”.

        If this is “none”, then proxies are not used.

        If it is “auto”, the autoconfiguration URL described by the
        “autoconfig-url” key is used.

        If it is “manual”, then the proxies described by
        “/system/proxy/http”, “/system/proxy/https”,
        “/system/proxy/ftp” and “/system/proxy/socks” will be used.
        Each of the 4 proxy types is enabled if its “host” key is
        non-empty and its “port” key is non-0.

        If an http proxy is configured, but an https proxy is not,
        then the http proxy is also used for https.

        If a SOCKS proxy is configured, it is used for all protocols,
        except that the http, https, and ftp proxy settings override
        it for those protocols only.
      </description>
    </key>
    <key name="autoconfig-url" type="s">
      <default>''</default>
      <summary>Automatic proxy configuration URL</summary>
      <description>
        URL that provides proxy configuration values. When mode is
        “auto”, this URL is used to look up proxy information for all
        protocols.
      </description>
    </key>
    <key name="ignore-hosts" type="as">
      <default>[ 'localhost', '127.0.0.0/8', '::1', '.tcbs.com.vn', 'tcbs.com.vn' ]</default>
      <summary>Non-proxy hosts</summary>
      <description>
        This key contains a list of hosts which are connected to directly,
        rather than via the proxy (if it is active). The values can be
        hostnames, domains (using an initial wildcard like *.foo.com), IP host
        addresses (both IPv4 and IPv6) and network addresses with a netmask
        (something like 192.168.0.0/24).
      </description>
    </key>
    <key name="use-same-proxy" type="b">
      <default>true</default>
      <summary>Unused; ignore</summary>
      <description>
        This key is not used, and should not be read or modified.
      </description>
    </key>
  </schema>
  <schema id="org.gnome.system.proxy.http" path="/system/proxy/http/">
    <key name="enabled" type="b">
      <default>false</default>
      <summary>Unused; ignore</summary>
      <description>
        This key is not used; HTTP proxying is enabled when the host
        key is non-empty and the port is non-0.
      </description>
    </key>
    <key name="host" type="s">
      <default>'10.105.1.14'</default>
      <summary>HTTP proxy host name</summary>
      <description>
        The machine name to proxy HTTP through.
      </description>
    </key>
    <key name="port" type="i">
      <range min="0" max="65535"/>
      <default>3129</default>
      <summary>HTTP proxy port</summary>
      <description>
        The port on the machine defined by “/system/proxy/http/host” that you
        proxy through.
      </description>
    </key>
    <key name="use-authentication" type="b">
      <default>false</default>
      <summary>Authenticate proxy server connections</summary>
      <description>
        If true, then connections to the proxy server require authentication.
        The username/password combo is defined by
        “/system/proxy/http/authentication-user” and
        “/system/proxy/http/authentication-password”.

        This applies only to the http proxy; when using a separate
        https proxy, there is currently no way to specify that it
        should use authentication.
      </description>
    </key>
    <key name="authentication-user" type="s">
      <default>''</default>
      <summary>HTTP proxy username</summary>
      <description>
        User name to pass as authentication when doing HTTP proxying.
      </description>
    </key>
    <key name="authentication-password" type="s">
      <default>''</default>
      <summary>HTTP proxy password</summary>
      <description>
        Password to pass as authentication when doing HTTP proxying.
      </description>
    </key>
  </schema>
  <schema id="org.gnome.system.proxy.https" path="/system/proxy/https/">
    <key name="host" type="s">
      <default>'10.105.1.14'</default>
      <summary>Secure HTTP proxy host name</summary>
      <description>
        The machine name to proxy secure HTTP through.
      </description>
    </key>
    <key name="port" type="i">
      <range min="0" max="65535"/>
      <default>3129</default>
      <summary>Secure HTTP proxy port</summary>
      <description>
        The port on the machine defined by “/system/proxy/https/host” that you
        proxy through.
      </description>
    </key>
  </schema>
  <schema id="org.gnome.system.proxy.ftp" path="/system/proxy/ftp/">
    <key name="host" type="s">
      <default>'10.105.1.14'</default>
      <summary>FTP proxy host name</summary>
      <description>
        The machine name to proxy FTP through.
      </description>
    </key>
    <key name="port" type="i">
      <range min="0" max="65535"/>
      <default>3129</default>
      <summary>FTP proxy port</summary>
      <description>
        The port on the machine defined by “/system/proxy/ftp/host” that you
        proxy through.
      </description>
    </key>
  </schema>
  <schema id="org.gnome.system.proxy.socks" path="/system/proxy/socks/">
    <key name="host" type="s">
      <default>''</default>
      <summary>SOCKS proxy host name</summary>
      <description>
        The machine name to use as a SOCKS proxy.
      </description>
    </key>
    <key name="port" type="i">
      <range min="0" max="65535"/>
      <default>0</default>
      <summary>SOCKS proxy port</summary>
      <description>
        The port on the machine defined by “/system/proxy/socks/host” that you
        proxy through.
      </description>
    </key>
  </schema>
</schemalist>
EOF
sudo -S glib-compile-schemas /usr/share/glib-2.0/schemas

  grep PATH /etc/environment > anttproxy.t;
  PROXY_HOST=10.105.1.14
  PROXY_PORT=3129
  printf \
  "http_proxy=http://$PROXY_HOST:$PROXY_PORT/\n\
  https_proxy=http://$PROXY_HOST:$PROXY_PORT/\n\
  ftp_proxy=http://$1:$2/\n\
  no_proxy=\"localhost,127.0.0.1,localaddress,.tcbs.com.vn,tcbs.com.vn,.localdomain.com\"\n\
  HTTP_PROXY=http://$PROXY_HOST:$PROXY_PORT/\n\
  HTTPS_PROXY=http://$PROXY_HOST:$PROXY_PORT/\n\
  FTP_PROXY=http://$PROXY_HOST:$PROXY_PORT/\n\
  NO_PROXY=\"localhost,127.0.0.1,localaddress,.tcbs.com.vn,tcbs.com.vn,.localdomain.com\"\n" >> anttproxy.t;

  cat anttproxy.t > /etc/environment;
  printf \
  "Acquire::http::proxy \"http://$PROXY_HOST:$PROXY_PORT/\";\n\
  Acquire::ftp::proxy \"ftp://$PROXY_HOST:$PROXY_PORT/\";\n\
  Acquire::https::proxy \"https://$PROXY_HOST:$PROXY_PORT/\";\n" > /etc/apt/apt.conf.d/95proxies;
  rm -rf anttproxy.t;
}

function antt_iptables()
{
    IPT=/sbin/iptables
    $IPT -F
    $IPT -P OUTPUT DROP                                                    
    $IPT -P INPUT DROP                                                 
    $IPT -P FORWARD DROP
    #Out
    $IPT -A OUTPUT --out-interface lo -j ACCEPT                            
    $IPT -A OUTPUT --out-interface tap0 -j ACCEPT
    $IPT -A OUTPUT --out-interface tun0 -j ACCEPT            
    $IPT -A OUTPUT -d 52.148.89.165 -p tcp --dport 1194 -j ACCEPT                           
    $IPT -A OUTPUT -d 52.148.89.165 -p udp --dport 1194 -j ACCEPT
    $IPT -A OUTPUT -d 13.76.31.219 -p tcp --dport 1194 -j ACCEPT      # Openvpnas                         
    $IPT -A OUTPUT -d 13.76.31.219 -p udp --dport 1194 -j ACCEPT      # Openvpnas
    $IPT -A OUTPUT -d 10.105.1.14 -p tcp --dport 3129 -j ACCEPT                           
    $IPT -A OUTPUT -d 10.105.1.14 -p udp --dport 3129 -j ACCEPT                              
    $IPT -A OUTPUT -d 8.8.8.8 -p tcp --dport 53 -j ACCEPT                    
    $IPT -A OUTPUT -d 8.8.8.8 -p udp --dport 53 -j ACCEPT
    $IPT -A OUTPUT -d 10.14.2.23 -p tcp --dport 4505 -j ACCEPT         # Ket noi den master Server           
    $IPT -A OUTPUT -d 10.14.2.23 -p udp --dport 4505 -j ACCEPT         # Ket noi den master Server
    $IPT -A OUTPUT -d 10.14.2.23 -p tcp --dport 4506 -j ACCEPT         # Ket noi den master Server           
    $IPT -A OUTPUT -d 10.14.2.23 -p udp --dport 4506 -j ACCEPT         # Ket noi den master Server
    #In
    $IPT -A INPUT --in-interface lo -j ACCEPT                               
    $IPT -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
    $IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
}

function antt_blockusb()
{
  chmod 444 /media/
}

function antt_cert()
{
cat << EOF > /root/ca_antt.crt
-----BEGIN CERTIFICATE-----
MIIDwzCCAqugAwIBAgIJALq+UD5AxFHNMA0GCSqGSIb3DQEBCwUAMHgxCzAJBgNV
BAYTAlZOMQswCQYDVQQIDAJWTjELMAkGA1UEBwwCSE4xDTALBgNVBAoMBFRDQlMx
DTALBgNVBAsMBFRDQlMxDTALBgNVBAMMBEFudHQxIjAgBgkqhkiG9w0BCQEWE3F1
YW5ndmFAdGNicy5jb20udm4wHhcNMjEwMTExMDMyNzIwWhcNMjYwMTEwMDMyNzIw
WjB4MQswCQYDVQQGEwJWTjELMAkGA1UECAwCVk4xCzAJBgNVBAcMAkhOMQ0wCwYD
VQQKDARUQ0JTMQ0wCwYDVQQLDARUQ0JTMQ0wCwYDVQQDDARBbnR0MSIwIAYJKoZI
hvcNAQkBFhNxdWFuZ3ZhQHRjYnMuY29tLnZuMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEArfTJdXsSQUWsBbZy5piPUgOq6F8ZBZmcUv/J+y0KfLgFfz7R
SlN2KqIdfTwXrG4WdBBVaXSwsD4n8aDO4p7F2lbMR9T1VzG8IiATqGhKVV/AKnlq
Z3pYteAzx9nDrUgkMepsF87McjoR+/EicL9zTNr1/FhZre3INsg7RAgq4tbezq+N
yT0gqPIJXFA+H/AzNfBkeJ/JXxRHLPJRCbpBU2jLuhj1vBHfnzX0+Hal3m4GBpbg
w/0n2TLmcM6s7fv2TcsRvyu85niTeV8PdPqByCFDFNXRK4iY1q+aJP/iI0M1k0ZR
k7HJBGEPlDOfMSRAyuLZVDT340UzF8MQfc4aBQIDAQABo1AwTjAdBgNVHQ4EFgQU
es5IZXMWG6EnSWVmj7aMzmki+KMwHwYDVR0jBBgwFoAUes5IZXMWG6EnSWVmj7aM
zmki+KMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAg8R1zZ/1Mliy
ntgv2RBxSr5Tsg5V6c9MLMS4u+DioR0++5aWj5Z+bNnYICy1Uz+2b5BSgWnsppJV
jUDfibngH5YUsOnY8wzdbspnqUPEnr6RgpiiRVh3qMLSV8O6tR6HRqdcrphZe2h5
Bm5kXJmcg1/CX/JbqLGDjGmT5j/FwQSJH22UTUgKoyy4y4Le8R8HtMYtcjHSvJvG
gzaW0QhvwFLKGppUWOTQTNuP3DpGRS0YuPKuP/xz0ZOQedKyPJu/7HMmiF2GZao+
3bCnljl0AAcAbhxOhn2h3OgcUf8ll8qGh9sCS4taAM6lrvCZJkZQ+ydoR6efcsRA
qq0vhTCu7Q==
-----END CERTIFICATE-----
EOF

cat << EOF > /usr/lib/firefox/distribution/policies.json
{
 "policies": {
      "BlockAboutConfig": true,
      "BlockAboutAddons": true,
      "BlockAboutProfiles": true,
      "Proxy": {
      "Mode": "manual",
      "Locked": true,
      "HTTPProxy": "10.105.1.14:3129",
      "UseHTTPProxyForAllProtocols": false,
      "SSLProxy": "10.105.1.14:3129",
      "FTPProxy": "10.105.1.14:3129",
      "Passthrough": "localhost"
    },
      "Certificates": {
      "Install": ["ca_antt.crt", "/root/ca_antt.crt"]
    },
      "Homepage": {
      "URL": "https://www.tcbs.com.vn",
      "Locked": true,
      "StartPage": "previous-session"
    }
 }
}
EOF
    mkdir /usr/lib/mozilla/certificates
    cp /root/ca_antt.crt /usr/lib/mozilla/certificates
    mkdir /usr/share/ca-certificates/antt
    cp /root/ca_antt.crt /usr/share/ca-certificates/antt/
    echo "antt/ca_antt.crt" >> /etc/ca-certificates.conf
    update-ca-certificates
}

function antt_confMaster()
{
  echo "master: 10.14.2.23" >> /etc/salt/minion
  MAC=$(ip link | sed -n "/BROADCAST.*state UP/{n;p}" | tail -1 | tr -s " " | cut -d" " -f3)
  echo "$MAC" > /etc/salt/minion_id

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
antt_proxy
antt_iptables
antt_blockusb
antt_confMaster


#
# MAIN
#

iptables-persistent save

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
