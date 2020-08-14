#!/bin/bash

# Parses basic OS scan "nmap -O"

# Grab input from cmd or default file
f_inputFile=${1:-NMAP_all_hosts.txt}

# Regular expressions for getting IP and services
# ips: "nmap scan report for <ip>"
# service: "<port>/<protocol> <state> <name>"
str_regex_getIp="^nmap scan report for .+$";
str_regex_getService="^[0-9]+/[a-z]+";

# Two temporary files are created
# temp stores everything 
# serviceIps stores ips by service
f_serviceIps=$(mktemp)
f_temp=$(mktemp)

# Read the input file and grab the IP's and services.
# When a service is found, store it with the IP of the 
# host if the temp file. Each line in the temp file 
# will be in the following format:
# <service name> <port>/<protocol> <ip of host>
while read line; do
	# Convert each line to lowercase for sorting later
	str_lowerLine=$(echo "$line" | tr '[:upper:]' '[:lower:]')
	
	# If the line matches an host line get the IP
	# Else get the service append to temp file with most recent
	# captured IP.
	if [[ $str_lowerLine =~ $str_regex_getIp ]]; then
		str_ip=$(echo $str_lowerLine | cut -d " " -f 5)
	elif [[ $str_lowerLine =~ $str_regex_getService ]]; then
		str_servicePortProt=$(echo $str_lowerLine | cut -d " " -f 1)
		str_serviceName=$(echo $str_lowerLine | cut -d " " -f 3)
		echo $str_serviceName $str_servicePortProt $str_ip >> $f_temp
	fi
done < $f_inputFile

# Produce a total count of each service sorted by most to least
cat $f_temp | cut -d " " -f 1,2 | sort -b | uniq -c | sort -bnr

# Sort services store in the service file. 
cat $f_temp | sort -b > $f_serviceIps

# Declare and create global variable to store service
# This is used in the following while loop to check
# If a new service has been detected.
declare STR_SERVICE
export STR_SERVICE

# Read the sorted service ip file. When a new service is found
# print the service, the "==" and set the global variable to
# the new service detected. Always print the IPs
while read line; do
	str_tempService=$(echo $line | cut -d " " -f 1,2)
	if [[ $str_tempService != $STR_SERVICE ]]; then
		echo " "	
		echo $str_tempService
		echo "================"
		STR_SERVICE=$str_tempService
	fi
	
	echo $line | cut -d " " -f 3
done < $f_serviceIps

# Cleanup temp files and globals
rm $f_serviceIps
rm $f_temp
unset STR_SERVICE
