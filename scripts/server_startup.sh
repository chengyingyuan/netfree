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

export NETFREE_USERNAME
export NETFREE_PASSWORD

PROG=$TOPDIR/src/netfree_udp
while (( 1 )); do
  $PROG -i $TUN_DEV -p $APP_PORT -u -d 
done
