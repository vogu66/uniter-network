#!/bin/sh

# Structure of the program:
# 0.0 Add a computer to the fold if not there yet -- local commands
# 0.1 Update unison and ssh if local install and not system and internet available
# 1.  Detect and verify connected computers (ssh) (ask other computers for their own connection abilities)
# 1.1 Sync list of computers between connected computers
# 2.  Select computers to sync backup
# 3.  Populate files to sync (take tree file list to sync from all the connected computers)
# 3.  Make syncing graphs of the various file trees to sync to ensure latest files on every device
# 4.  Detect connection types (i.e. whether direct ethernet bridging that can be let unsecure or ssh required)
# 5.  Start unison processes to sync all files. Careful how to handle concurrent processes and conflicts.


# 0.0 Add a computer to the fold if not there yet -- local commands
# 0.1 Update unison and ssh if local install and not system and internet available

# 1.  Detect and verify connected computers (ssh) (ask other computers for their own connection abilities)
# First get current ip address so that the ipv4 prefix is known
# use ip addr

addresses=$(ip addr | awk '/inet / {
ip=$2
sub("/.*", "", ip)
prefix=ip
n=split(prefix, a, ".")
sub("."a[n], "", prefix)
print ip
print prefix
}')
echo $addresses
# echo 192.168.1.{1..254}|xargs -n1 -P0 ping -c1 -w1|grep "bytes from"



# 1.1 Sync list of computers between connected computers
# 2.  Select computers to sync backup
# 3.  Populate files to sync (take tree file list to sync from all the connected computers)
# 3.  Make syncing graphs of the various file trees to sync to ensure latest files on every device
# 4.  Detect connection types (i.e. whether direct ethernet bridging that can be let unsecure or ssh required)
# 5.  Start unison processes to sync all files. Careful how to handle concurrent processes and conflicts.