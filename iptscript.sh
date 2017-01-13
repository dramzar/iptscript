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
if ! hash iptables 2>/dev/null; then
  echo "iptables not installed..."
  exit 2
fi


################################
# Variables
################################
inputdrop=true
outputdrop=true
getlisteningports=true
addcommonrules=true
addhttphttps=true
sysmdfolder=/lib/systemd/system/
sysmdservice=iptables-restore.service
sysmdfile=${sysmdfolder}${sysmdservice}
upsfolder=/etc/init/
restorefile=/etc/iptables.save
tmpfile=/tmp/iptables.save
configfile="iptscript.conf"

###############################
# Load variables from config file
###############################
function load_conf {
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
}
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
Description=IPTABLES save and restore service
After=network.target

[Service]
Type=simple
RemainAfterExit=True
ExecStart=/sbin/iptables-restore $restorefile
ExecStop=$restorefile.sh $restorefile

[Install]
WantedBy=multi-user.target"
###

  echo "${content}" >$sysmdfile

# BASH File Creation

  echo "Creating BASH file..."

###
content="
#!/bin/bash
/sbin/iptables-save > $tmpfile
newtxt=''

while read p; do
        if [[ \"\${newtxt#*\$p}\" == \"\$newtxt\" ]]; then
                newtxt=\"\${newtxt}\${p}\n\"
        fi
done <$tmpfile

echo -e \$newtxt > $restorefile
rm $tmpfile
chmod 600 $restorefile"
###

  echo "${content}" > $restorefile.sh

  chmod 700 $restorefile.sh
}

# Function to initialize systemd service
function init_sysmd_service {

  echo "Saving initial iptables restore file..."
  iptables-save > $restorefile
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
# iptables restore script

description     \"restore iptables saved rules\"

start on network or runlevel [2345]

exec /sbin/iptables-restore $restorefile"

echo "${content}" > ${upsfolder}iptables-restore.conf

  # Shutdown script

  content="
# iptables save script

description     \"save iptables rules\"

start on runlevel [06]

exec $restorefile.sh"

  echo "${content}" > ${upsfolder}iptables-save.conf

# Creating Bash file
  content="#!/bin/bash
/sbin/iptables-save > $tmpfile
newtxt=''

while read p; do
        if [[ \"\${newtxt#*\$p}\" == \"\$newtxt\" ]]; then
                newtxt=\"\${newtxt}\${p}\n\"
        fi
done <$tmpfile

echo -e \$newtxt > $restorefile
rm $tmpfile
chmod 600 $restorefile"

  echo "${content}" > $restorefile.sh
  chmod 700 $restorefile.sh
}

# Function to add some common rules to iptables
function add_commonrules {
  echo "Adding common rules..."

  if [[ "$inputdrop" == true ]]; then
    #Accept packets comming in on the loopback interface
    iptables -A INPUT -i lo -j ACCEPT
    #Accept DNS lookup responces on udp
    iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT
    #Reject new ICMP requests
    iptables -A INPUT -p icmp --icmp-type echo-request -j REJECT --reject-with icmp-host-unreachable
    #Accept ICMP responces
    iptables -A INPUT -p icmp --icmp-type echo-reply -m state --state ESTABLISHED,RELATED -j ACCEPT
    #Accept established or related tcp packets
    iptables -A INPUT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
  elif [[ "$inputdrop" == false ]]; then
    #Drop new incoming tcp packets if they are not SYN
    iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
    #Drop fragmented packets
    iptables -A INPUT -f -j DROP
    #Drop malformed XMAS packets
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    #Drop NULL packets
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    #Reject new ICMP requests
    iptables -A INPUT -p icmp --icmp-type echo-request -j REJECT --reject-with icmp-host-unreachable
  fi

  if [[ "$outputdrop" == true ]]; then
    #Accept all packets on the loopback interface
    iptables -A OUTPUT -o lo -j ACCEPT
    #Accept DNS lookup requests on udp
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    #Accept new ICMP requests
    iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
    #Accept all packets from established or related sessions
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  fi
}

# Function to add the rules added by the get_listenports and user
function add_ownrules {
  echo "Adding user defined rules..."

  for ((i=0; i<${#addport[@]}; i++)); do
    iptables -A INPUT -p tcp --dport ${addport[$i]}  -s ${srcnet[$i]} -j ACCEPT
  done
}
# function to add OUTPUT rules to allow HTTP and HTTPS
function add_httphttps_rules {
  echo "Adding HTTP and HTTPS OUTPUT rules..."

  iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
  iptables -A OUTPUT -p tcp --dport 8080 -j ACCEPT
}

# Function to apply iptable default policy for INPUT and OUTPUT
function apply_policy {
  echo "Applying default INPUT/OUTPUT policies..."

  if [[ "$inputdrop" == true ]]; then
    iptables -P INPUT DROP
  else
    iptables -P INPUT ACCEPT
  fi

  if [[ "$outputdrop" == true ]]; then
    iptables -P OUTPUT DROP
  else
    iptables -P OUTPUT ACCEPT
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
		addport[$ports]="YES"
		srcnet[$ports]="any"

	done

	# Get list of listening ports with port number
	tmpport=$(netstat -vatn | grep -i 0.0.0.0: | awk '{print $4}' | awk -F: '{print $2}')
	ports=0
	for pp in $tmpport; do
		ports=$(($ports+1))
		openpp[$ports]=$pp
	done

	(( ports+=1 )) # Add one to ports since its used in the loop later

	# Start loop so the user can choose what ports to add to the INPUT list
	# May cause trouble if the list of listening ports are long...
	while :
	do
		clear
		echo "What input ports should be added to the iptables list?"
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
				echo -n "Service (empty for 'Custom'): "
				read name
				if [ -z $name ]; then
					name="Custom"
				fi
				echo -n "Port: "
				read port
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
					echo "Please note that no check will be done on the entry so be sure that its a valid network."
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

# Load configuration
load_conf

# Get the listening ports
if [[ "$getlisteningports" == true ]]; then
  get_listenports
fi

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
if [[ $initsystem == upstart ]]; then
  create_restore_files_systemd
  init_sysmd_service
elif [[ $initsystem == systemd ]]; then
  create_restore_files_upstart
fi

echo "All done. Here are the iptables rules:"
iptables -L INPUT
iptables -L OUTPUT

echo "Please note that any duplicated rules should be gone after a reboot."
