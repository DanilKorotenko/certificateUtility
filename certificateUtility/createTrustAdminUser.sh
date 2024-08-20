#!/bin/sh

function findUniqueUID()
{
    userIDS=( $(/usr/bin/dscacheutil -q user | grep uid | awk '{print $2}' | sort -n) )

    array_size=${#userIDS[@]}
    last_index=$(( array_size-1))
    last_element=${userIDS[$last_index]}

    result=$((last_element + 1))

    echo $result
}

uniqueUID=$(findUniqueUID)

dscl . -create /Users/trustadmin
dscl . -create /Users/trustadmin UserShell /bin/bash
dscl . -create /Users/trustadmin UniqueID "$uniqueUID"
dscl . -create /Users/trustadmin PrimaryGroupID 0
dscl . -passwd /Users/trustadmin pass123456

dscl . -append /Groups/admin GroupMembership trustadmin

#while [ $(dscacheutil -q user | grep trustadmin) -ne 0 ]
#do
#    echo "Wait until user created"
#    sleep 1
#done
