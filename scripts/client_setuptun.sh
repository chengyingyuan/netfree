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

ip tuntap add dev $TUN_DEV mode $TUN_MODE user $TUN_DEV_USER group $TUN_DEV_GROUP 
ip link set $TUN_DEV up
ip addr add $TUN_CLIENT_ADDR/24 dev $TUN_DEV
