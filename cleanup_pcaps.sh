#!/bin/sh
#
# (c) 2013 visiblerisk
# sconzo@visiblerisk.com
#
# todo - read from same config file as process that starts capture daemon so PCAP_DIR
#        gets set correctly
#

safe=0
PCAP_DIR=/data/capture_test
LOCKFILE=/tmp/session-cleanup.lock
TIMEBASED=0
WINDOW=7200 #minutes in 5 days - 1440 minutes per day

if [ -e $LOCKFILE ]; then
  exit
fi

touch $LOCKFILE

cd $PCAP_DIR

if [ $TIMEBASED -eq 1 ]; then
  # remove all pcap files older than $WINDOW
  find ./ -name "*.pcap" -mmin +$WINDOW -print0 | xargs -0 -r rm -f
  # cleanup any empty directories
  find ./ -type d -empty -print0 | xargs -0 -r rmdir
else
  while [ $safe -ne 1 ]
  do
    used=`df -h . 2>&1 | tail -n1 | awk '{print $5}' | cut -d '%' -f 1`
    if [ $used -gt 85 ]; then
      echo "removing files"
      # Find and remove the 10000 oldest files
      find . -type f -printf "%T@ %P\n" | sort -nr | tail -10000 | awk '{print $2;}' | xargs -r rm -f
      # cleanup any empty directories
      find ./ -type d -empty -print0 | xargs -0 -r rmdir
    else
      safe=1
    fi
  done
fi

rm $LOCKFILE
exit
