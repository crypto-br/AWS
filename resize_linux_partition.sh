#!/bin/bash

# @cryptobr 2019
# Expand volumes for T2 Linux instance
# Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/recognize-expanded-volume-linux.html

echo "Volumes Instances"
echo ""
lsblk
echo ""
echo "Select your partition ex: xvda"
read NAME
echo "Select number partition ex: for xvda1 enter 1"
read NUMBER
echo "Expand partition..."
sleep 1
echo ""
sudo growpart /dev/$NAME $NUMBER
sudo resize2fs /dev/$NAME$NUMBER
echo ""
echo "Show new size partition"
df -h
