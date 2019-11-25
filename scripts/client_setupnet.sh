#!/bin/bash
# 
# Route raspberry pi wifi ap traffic to tup device
#
# http://www.techpository.com/linux-configuring-multiple-default-routes-in-linux/
# 

MYDIR=$(realpath $(dirname $0))
TOPDIR=$(dirname $MYDIR)
export TOPDIR

CONFIG_FILE=$MYDIR/netfree_config.sh
if [ ! -f $CONFIG_FILE ]; then
  echo "Config file $CONFIG_FILE not found"
  exit 1
fi
source $CONFIG_FILE

echo 1 > /proc/sys/net/ipv4/ip_forward

# Create a new route table
RT_FILE=/etc/iproute2/rt_tables
exists=$(grep "^1 admin" $RT_FILE)
if [ "x$exists" = "x" ]; then
	echo "1 admin" >> $RT_FILE
	echo "Created route table 'admin'"
fi

# Setup route table
ip route add $CLIENT_LAN_NET dev $CLIENT_LAN_DEV src $CLIENT_LAN_DEV_ADDR table admin
ip route add default via $TUN_SERVER_ADDR dev $TUN_DEV table admin
ip rule add from $CLIENT_LAN_DEV_ADDR/32 table admin
ip rule add from $CLIENT_LAN_NET table admin
ip rule add to $CLIENT_LAN_DEV_ADDR/32 table admin
ip rule add to $CLIENT_LAN_NET table admin
ip rule show

