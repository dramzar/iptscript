#!/bin/bash
#################################
#
#
#
#
#
#################################

# Making sure script is run as root/su
if [[ $EUID > 0 ]]; then
  echo "Please run the script as root"
  exit 1
fi

# Making sure iptables are installed
if ! hash nft 2>/dev/null; then
  echo "nftables not installed..."
  exit 2
fi


################################
# Variables
################################
nfttablename="nfts"
inputdrop=true
outputdrop=true
getlisteningports=true
addcommonrules=true
addhttphttps=true
sysmdfolder=/lib/systemd/system/
sysmdservice=iptables-restore.service
sysmdservice_nft=nftables-restore.service
upsfolder=/etc/init/
restorefile=/etc/iptables.save
restorefile_nft=/etc/nftables.save
# Variable not included in config file
configfile="iptscript.conf"
nftexec=$(whereis nft | awk {'print $2'})
###############################
# Load variables from config file
###############################
if [[ -f $configfile ]]; then
        shopt -s extglob
        tr -d '\r' < $configfile > $configfile.unix
        while IFS='= ' read lhs rhs
        do
                if [[ ! $lhs =~ ^\ *# && -n $lhs ]]; then
                        rhs="${rhs%%\#*}"
                        rhs="${rhs%%*( )}"
                        rhs="${rhs%\"*}"
                        rhs="${rhs#\"*}"
                        declare $lhs="$rhs"
                fi
        done < $configfile.unix
        rm $configfile.unix
else
	echo "Unable to find file... using values in script file..."
fi
# Define some variabled that use the other variables
sysmdservice=$sysmdservice_nft
sysmdfile=${sysmdfolder}${sysmdservice}
nftin="nft add rule $nfttablename input"
nftout="nft add rule $nfttablename output"
restorefile=$restorefile_nft

###############################
# Function declaration
###############################

# Function to try and figure out what init system is in use
function get_initsystem {
        if [[ $(/sbin/init --version 2>/dev/null) == *upstart* ]]; then echo upstart;
        elif [[ $(systemctl 2>/dev/null) == *-.mount* ]]; then echo systemd;
        elif [[ -f /etc/init.d/cron && ! -h /etc/init.d/cron ]]; then echo sysv-init;
        else echo unknown; fi
}

# Function to create the service for systemd
function create_restore_files_systemd {
# Service File Creation
  echo "Creating save and restore scripts for systemd."
  echo "Creating service file..."

###
content="
[Unit]
Description=NFTABLES save and restore service
After=network.target

[Service]
Type=simple
RemainAfterExit=True
ExecStart=$nftexec -f $restorefile
ExecReload=$nftexec -f $restorefile
ExecStop=$restorefile.sh

[Install]
WantedBy=multi-user.target"
###

  echo "${content}" >$sysmdfile

# BASH File Creation

  echo "Creating BASH file..."

###
content="#!/bin/bash
echo \"flush ruleset\" > $restorefile
$nftexec list ruleset >> $restorefile

chmod 600 $restorefile"
###

  echo "${content}" > $restorefile.sh

  chmod 700 $restorefile.sh
}

# Function to initialize systemd service
function init_sysmd_service {

  echo "Saving initial nftables restore file..."
  echo "flush ruleset" > $restorefile
  $nftexec list ruleset >> $restorefile
  chmod 600 $restorefile

  echo "Enabling and starting restore service..."
  systemctl enable $sysmdservice
  systemctl start $sysmdservice

}

# Function to create the start and stop script used by upstart
function create_restore_files_upstart {
  # Startup script

  echo "Creating save and restore scripts for Upstart."
  content="
# nftables restore script

description     \"restore nftables saved rules\"

start on network or runlevel [2345]

exec $nftexec -f $restorefile"

echo "${content}" > ${upsfolder}nftables-restore.conf

  # Shutdown script

  content="
# nftables save script

description     \"save nftables rules\"

start on runlevel [06]

script
	echo \"flush ruleset\" > $restorefile
	$nftexec list ruleset >> $restorefile
	chmod 600 $restorefile
end script"

  echo "${content}" > ${upsfolder}nftables-save.conf

}

# Function to create the table and chains in nftables
function init_nftable {
  echo "Initilizing the table in nftables..."

  # First try and delete the table if it already exists
  nft delete table $nfttablename 2>/dev/null

  # Add the table and then the two chains 'input' and 'output'
  nft add table $nfttablename
  nft add chain $nfttablename input \{ type filter hook input priority 0\; \}
  nft add chain $nfttablename output \{ type filter hook output priority 0\; \}
}

# Function to add some common rules to nftables
function add_commonrules {
  echo "Adding common rules..."

  if [[ "$inputdrop" == true ]]; then
    #Accept packets comming in on the loopback interface
    $nftin iif lo accept
    #Accept DNS lookup responces on udp
    $nftin udp sport 53 ct state established,related accept
    #Reject new ICMP requests
    $nftin icmp type echo-request reject with icmp type host-unreachable
    #Accept ICMP responces
    $nftin icmp type echo-reply ct state established,related accept
    #Accept established or related packets
    $nftin ct state established,related accept
  elif [[ "$inputdrop" == false ]]; then
    #Drop new incoming tcp packets if they are not SYN
    $nftin tcp flags != syn ct state new drop
    #Drop malformed XMAS packets
    $nftin tcp flags \& \(fin\|syn\|rst\|psh\|ack\|urg\) \> urg drop
    #Drop NULL packets
    $nftin tcp flags \& \(fin\|syn\|rst\|psh\|ack\|urg\) \< fin drop
    #Reject new ICMP requests
    $nftin icmp type echo-request reject with host-unreachable
  fi

  if [[ "$outputdrop" == true ]]; then
    #Accept all packets on the loopback interface
    $nftout oif lo accept
    #Accept DNS lookup requests on udp
    $nftout udp dport 53 accept
    #Accept new ICMP requests
    $nftout icmp type echo-request accept
    #Accept all packets from established or related sessions
    $nftout ct state established,related accept
  fi
}

# Function to add the rules added by the get_listenports and user
function add_ownrules {
  echo "Adding user defined rules..."

  for ((i=0; i<${#addport[@]}; i++)); do
    if [[ ${srcnet[$i]} == "any" ]]; then
      $nftin tcp dport ${addport[$i]} accept
    else
      $nftin tcp dport ${addport[$i]} ip saddr ${srcnet[$i]} accept
    fi
  done
}
# function to add OUTPUT rules to allow HTTP and HTTPS
function add_httphttps_rules {
  echo "Adding HTTP and HTTPS OUTPUT rules..."

  $nftout tcp dport {80, 443} accept
}

# Function to apply default policy for INPUT and OUTPUT chains
function apply_policy {
  echo "Applying default INPUT/OUTPUT policies..."

  if [[ "$inputdrop" == true ]]; then
    nft add chain $nfttablename input \{ type filter hook input priority 0 \; policy drop\; \}
  fi

  if [[ "$outputdrop" == true ]]; then
    nft add chain $nfttablename output \{ type filter hook output priority 0 \; policy drop\; \}
  fi
}

# Function to add input rules based on listening ports and the user
function get_listenports {
	echo "Getting listening ports..."
	# Get list of listening ports with name.
	tmpport=$(netstat -vat | grep -i 0.0.0.0: | awk '{print $4}' | awk -F: '{print $2}')
	ports=0
	for pn in $tmpport; do
		ports=$(($ports+1))
		openpn[$ports]=$pn

	done

	# Get list of listening ports with port number
	tmpport=$(netstat -vatn | grep -i 0.0.0.0: | awk '{print $4}' | awk -F: '{print $2}')
	ports=0
	for pp in $tmpport; do
		ports=$(($ports+1))
		openpp[$ports]=$pp
		addport[$ports]="YES"
		srcnet[$ports]="any"
	done

	(( ports+=1 )) # Add one to ports since its used in the loop later

	# Start loop so the user can choose what ports to add to the INPUT list
	# May cause trouble if the list of listening ports are long...
	while :
	do
		clear
		echo "What input ports should be added to the nftables rules?"
		echo "Here are the ports currently listening for tcp connections:"
		echo -e "Number: Service (Port)\t\tAdd\tSourcenetwork"
		for ((i=1; i<$ports; i++)); do
			echo -e "$i:\t${openpn[$i]} (${openpp[$i]})\t\t[${addport[$i]}]\t${srcnet[$i]}"
		done
		if [[ $ports == 1 ]]; then
			echo "No listening ports found..."
		fi
		echo ""
		echo "$ports: All done."
		echo "0: Add custom port"
		echo ""
		echo -n "Enter a number to edit the entry: "
		read choise
		if [ $choise -ge 0 -a $choise -le $ports ]; then # Check if the input is within the range. strings will result in a error but should not be visible because of the 'clear' in the begining of the loop
			if [[ $choise == $ports ]]; then
				break
			elif [ $choise -eq 0 ]; then
				echo "New sevice. Please note that incorrect entrys may cause the script to fail..."
				echo -n "Service (empty for 'Custom'): "
				read name
				if [ -z $name ]; then
					name="Custom"
				fi
				echo -n "Port (1-65535): "
				read port
				if [ $port -ge 1 -a $port -le 65535 ]; then
				echo -n "Source network (empty for 'any'): "
					read src
					if [ -z $src ]; then
						src="any"
					fi

					# Adding the new port
					openpn[$ports]=$name
					openpp[$ports]=$port
					addport[$ports]="YES"
					srcnet[$ports]=$src

					((ports+=1)) # Increase the number of ports after adding
				else
					echo "Only a singel port between 1 and 65535 are allowed"
					echo -n "Press enter to continue to the list..."
					read foo
				fi
			else # Edit selected rule
				echo -e "Service\t\tPort\tAdd\tSourcenetwork"
				echo -e "${openpn[$choise]}\t\t${openpp[$choise]}\t${addport[$choise]}\t${srcnet[$choise]}"
				echo ""
				echo "1: Switch if the enty should be added or not."
				echo "2: Change the source network."
				echo "3: Cancel"
				echo ""
				echo -n "Choose: "
				read entry
				if [ $entry -eq 1 ]; then
					if [[ ${addport[$choise]} == "YES" ]]; then
						addport[$choise]="NO"
					else
						addport[$choise]="YES"
					fi
				elif [ $entry -eq 2 ]; then
					echo "Please note that no check will be done on the entry, so be sure that it\'s a valid network."
					echo "Blank entry to cancel."
					echo ""
					echo -n "New sourece network: "
					read src
					if [ ! -z $src ]; then
						srcnet[$choise]=$src
					fi
				fi
			fi
		fi
	done

	# Change the 'YES' valued for the port numbers, clear the 'NO' values
	for ((i=1; i<$ports; i++)); do
		if [[ ${addport[$i]} == "YES" ]]; then
			addport[$i]=${openpp[i]}
		else
			addport[$i]=""
			srcnet[$i]=""
		fi
	done
	addport=(${addport[@]})
	srcnet=(${srcnet[@]})
}

# Checking what init system is used
initsystem=$(get_initsystem)
if [[ $initsystem == unknown ]]; then
	echo "Unable to determine what init system is running; exiting."
	exit 100
elif [[ $initsystem == upstart ]] ;then
	echo "Init system is upstart."
elif [[ $initsystem == systemd ]] ;then
	echo "Init system is systemd."
elif [[ $initsystem == sysv-init ]] ;then
	echo "Init system is sysv-init..."
	echo "This is not implemented yet..."
	exit 0
else
	echo "Unknown error..."
	exit 101
fi

# Get the listening ports
if [[ "$getlisteningports" == true ]]; then
  get_listenports
  echo "###############################"
fi

# Initilize the table and chains in nftables
init_nftable

# Add common rules
if [[ "$addcommonrules" == true ]]; then
  add_commonrules
  if [[ "$addhttphttps" == true && "$outputdrop" == true ]]; then
    add_httphttps_rules
  fi
fi

# Add custom rules
if [[ "$getlisteningports" == true ]]; then
  add_ownrules
fi

# Apply INPUT/OUTPUT policy
apply_policy

# Create services
if [[ $initsystem == systemd ]]; then
  create_restore_files_systemd
  init_sysmd_service
elif [[ $initsystem == upstart ]]; then
  create_restore_files_upstart
fi

echo "###############################"
echo "All done. Here are the nftables rules:"
nft list table $nfttablename
