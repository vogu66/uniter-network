#!/bin/zsh

# use port 46 → see /etc/ssh/sshd_config
PORT="46"

# open sshd on port 46
systemctl start sshd

# get my ip addresses
## get addresses, get only them from text, remove newlines, remove localhost
addresses=$(ip addr | awk '/inet / {                      
ip=$2
sub("/.*", "", ip)
print ip}' | paste -sd '|' -)

# get inet masks
# ip → get ip address
# awk → get only useful domain names
# paste → change it to a single line nicely
# awk → remove 127.0 which iw the first found
# nmap → find open ports addresses
# awk → get only the ip addresses
# grep → remove this pc
# paste → remove newlines cleanly
ip addr | awk '/inet / {print $2}' | paste -sd ' ' - | awk '{ $1=""; print}' | nmap -oG -  -p $PORT -iL - | awk '/open/ {print $2}' | grep -Ev $addresses| paste -sd ' ' -


# syncthing? Unison?