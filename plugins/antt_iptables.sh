#!/bin/bash
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