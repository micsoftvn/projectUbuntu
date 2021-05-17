#!/bin/bash
    cat << EOF > /etc/network/if-up.d/tun-up
#!/usr/bin/env bash
user_list=(\$(who | grep -E "\(:[0-9](\.[0-9])*\)" | awk '{print \$1 "@" \$NF}' | sort -u))
for user in \$user_list; do
username=\${user%@*}
su \$username -c 'notify-send "Canh bao" "Ban dang ket noi VPN vao he thong TCBS toan bo thong tin ket noi cua ban se deu duoc ghi log" -u critical -t 10000 -i /usr/share/hplip/data/images/32x32/warning.png'
done
EOF
