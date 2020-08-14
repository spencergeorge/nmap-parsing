#!/bin/gawk -f
# Parses basic OS scan: "nmap -O"

BEGIN {
	# Initialize services. A multidimensional associative array.
	# Stores all services, their counts, and IP's
	# Keys are in format:
	# counts: "<a process>,<a port/prot>,count"
	# ips: "<a process>,<a port/prot>,ips"
	services[""]="";

	# Stores IP of host one at a time. This is set once per host
	str_ip="";

	# Regular expressions for IPs and service definitions
	# service: <port>/<protocol>
	str_regex_getIp="^Nmap scan report for .+$";
	str_regex_getService="^[0-9]+/[a-zA-Z]+.*$";
	
	# Regular expressions for printing the output.
	# Used to test against key names in services collection.
	str_regex_keyCount="^[0-9a-zA-Z-]+,[0-9]+/[a-zA-Z]+,count";
	str_regex_keyIps="^[0-9a-zA-Z-]+,[0-9]+/[a-zA-Z]+,ips";
}
#PROCESS
{
	# If the line matches a host line grab the IP
	# else if the line matches a service, grab service and
	# add one to the count of that service and store the IP
	if (match($0,str_regex_getIp)) {
		str_ip=$(NF)
	}
	else if (match($0,str_regex_getService)) {
		# Store service name, port/prot convert to lower(for sorting)
		str_serviceName=tolower($3)
		str_servicePortProt=tolower($1)

		# Concatenate service names, ports & protocols to var str_keyName
		str_keyName=str_serviceName "," str_servicePortProt

		# Increment service count by 1
		services[str_keyName ",count"]++

		# Add IP to service list
		services[str_keyName ",ips"]=services[str_keyName ",ips"] str_ip "\n"
	}
}
END {
	# Set sorting order by value numerical descending for printing service totals
	PROCINFO["sorted_in"]="@val_num_desc"

	# For each service, print their total count
	for (key in services) {
		if (match(key, str_regex_keyCount)) {
			# Splits the key string and grab the service name		
			split(key, service, ",")
			print services[key] " " service[1] " " service[2]
		}
	}

	print "\n"

	# Set sorting order by index string ascending for printing service IP associations
	PROCINFO["sorted_in"]="@ind_str_asc"

	# For each service print the host IPs
	for (key in services) {
		if (match(key, str_regex_keyIps)) {
			# Splits the key string and grab the service name
			split(key, service, ",")
			print service[1] " " service[2]
			print "================"
			print services[key]
		}
	}
}
