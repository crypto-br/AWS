#!/bin/bash

# @cryptobr 2019
# @f1r3m4n 2019
# Expand volumes for T2 Linux instance
# Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/recognize-expanded-volume-linux.html
# Do not forget to install this package -> $ yum install cloud-utils-growpart xfsprogs

# Install dependencies
sudo yum install -y cloud-utils-growpart xfsprogs
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
# Select File System
echo "Enter 1 for (ext2,ext3,ext4) or 2 for (XFS):"
read fs
if [ $fs -eq 1 ]
then
        sudo resize2fs /dev/$NAME$NUMBER
else
        sudo xfs_growfs -d /dev/$NAME$NUMBER
fi
echo ""
echo "Show new size partition"
df -h
