#!/bin/sh
sudo iptables -t filter -F 
sudo iptables -t filter -X 
sudo iptables -t mangle -F
sudo iptables -t mangle -X 
sudo iptables -t nat -F 
sudo iptables -t nat -X 
sudo iptables -t raw -F 
sudo iptables -t raw -X

sudo iptables -A INPUT -p tcp --dport 80 -s 67.199.248.13 -j ACCEPT

sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

sudo iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m limit --limit 1/s -j ACCEPT 

sudo iptables -A FORWARD -p tcp --syn -m limit --limit 1/s --limit-burst 500 -j ACCEPT

sudo iptables -t filter -A INPUT -i lo -j ACCEPT 
sudo iptables -t filter -A OUTPUT -o lo -j ACCEPT

sudo iptables -t nat -A PREROUTING -p tcp --dport 8888 -j DNAT --to-destination :25565

sudo iptables -t filter -A INPUT -p tcp --dport 22 -s 128.46.104.20 -m state --state ESTABLISHED -j ACCEPT 
sudo iptables -t filter -A OUTPUT -p tcp --sport 22 -d 128.46.104.20 -m state --state NEW,ESTABLISHED -j ACCEPT

sudo iptables -A INPUT -i DROP 
sudo iptables -A OUTPUT -i DROP 
sudo iptables -A FORWARD -i DROP
