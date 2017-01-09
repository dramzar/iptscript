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
outfolder=/lib/systemd/system/
service_name=iptables-restore.service
outfile=${outfolder}${service_name}
restorefile=/etc/iptables.save
tmpfile=/tmp/iptables.save
configfile="iptscript.conf"

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

###############################
# Function declaration
###############################

function get_initsystem {
        if [[ '/sbin/init --version' =~ upstart ]]; then echo upstart;
        elif [[ $(systemctl) == *-.mount* ]]; then echo systemd;
        elif [[ -f /etc/init.d/cron && ! -h /etc/init.d/cron ]]; then echo sysv-init;
        else echo unknown; fi
}

function create_restore_files_systemd {
##############################
# Service File Creation
##############################
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

  echo "${content}" >$outfile

##############################
# BASH File Creation
##############################
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

echo -e \$newtxt > $outfile
rm $tmpfile"
###

  echo "${content}" > $restorefile.sh

  echo "chmod 600 $restorefile" >> $restorefile.sh
  chmod 700 $restorefile.sh

############################
# Finishing up
############################
  echo "Saving initial iptables restore file..."
  iptables-save > $restorefile
  chmod 600 $restorefile

  echo "Enabling and starting restore service..."
  systemctl enable $service_name
  systemctl start $service_name
}

function add_commonrules {
  #Drop new incoming tcp packets if they are not SYN
  iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
  #Drop fragmented packets
  iptables -A INPUT -f -j DROP
  #Drop malformed XMAS packets
  iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
  #Drop NULL packets
  iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
  #Accept packets comming in on the loopback interface
  iptables -A INPUT -i lo -j ACCEPT
  #Accept established or related packets
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
}


function get_listenports {
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
		echo ""
		echo -n "Enter a number to edit the entry: "
		read choise
		if [ $choise -gt 0 -a $choise -le $ports ]; then # Check if the input is within the range. strings will result in a error but should not be visible because of the 'clear' in the begining of the loop
			if [[ $choise == $ports ]]; then
				break
			fi
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
if [[ initsystem == unknown ]]; then
	echo "Unable to determine what init system is running exiting."
	exit 100
fi


