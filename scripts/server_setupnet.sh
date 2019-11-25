#!/bin/bash

MYDIR=$(realpath $(dirname $0))
TOPDIR=$(dirname $MYDIR)
export TOPDIR

CONFIG_FILE=$MYDIR/netfree_config.sh
if [ ! -f $CONFIG_FILE ]; then
  echo "Config file $CONFIG_FILE not found"
  exit 1
fi
source $CONFIG_FILE

# Search for internet interface, such as eth0, wlan1 etc.
WLANIF=$(route -n |grep "^0.0.0.0"|awk '{print $8}')

echo 1 > /proc/sys/net/ipv4/ip_forward

# Forward packages from client network to internet through nat
#iptables -F
#iptables -X
#iptables -Z
# Clear existing one if necessary
iptables -t nat -D POSTROUTING -s $CLIENT_LAN_NET -o $WLANIF -j MASQUERADE
iptables -t nat -A POSTROUTING -s $CLIENT_LAN_NET -o $WLANIF -j MASQUERADE

# Forward packages from internet to client network
route add -net $CLIENT_LAN_NET gw $TUN_CLIENT_ADDR
