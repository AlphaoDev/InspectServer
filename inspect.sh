#!/bin/bash

##############################################################################
#             Inspection script to scan remote or local machines.            #
# Make sur that you have ping, traceroute, nmap, whois, host and egrep tools #
##############################################################################

usage() {
echo -e "\nUsage: $0 -t <target>\n" >&2
exit 1
}

validity() {
echo -e "Target is not valid, please use an IP address or domain.\n" >&2
exit 1
}

down() {
echo -e "Target seems down, please try again.\n" >&2
exit 1
}

if [ $# = 2 ];then

    if [ $1 = "-t" ];then

        scriptname=$0
        target=$2
        ports="1-66535"

        # Informations about script
        echo -e "\n============================================================"
        echo -e "INSPECT HOST v1.0\n\nTarget is $target"
        echo -e "You are responsible for the actions performed by the script."
        echo -e "============================================================\n"

        # Check the validity of target
        ping -c1 $target &> /dev/null
        success=$?
        if ! [[ "$success" -eq 2 ]];then
            # Check the target type
            if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]];then
                type="ip"
            else
                type="domain"
            fi

            # Check if target is UP
            if [[ $(nmap -sn -Pn "$target" | grep "Host") =~ "Host is up" ]];then
                status="UP"
            else
                down
            fi
            # Check if target ping works
            ping -c1 $target &> /dev/null
            success=$?
            if ! [ "$success" -eq 1 ];then
                ping="PING OK"
            else
                ping="NO PING"
            fi

            # Check DNS
            if [ "$type" = "domain" ];then
                dns=$(host "$target" | grep "has address" | sed 's/has address/-/g')
            else
                dns=$(host "$target" | grep "domain" | sed 's/domain name pointer/-/g')
            fi

            # Check routes to join target
            NETPATH=(`traceroute -I -n "$target" | awk '{print $2}'`)
            bounce=1
            hops=()
            for i in "${NETPATH[@]}";do
                if [[ "$i" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]];then
                    if ! [[ "$i" == *" * "* ]];then
                        hops+=("\n   $bounce. $i")
                        bounce=$((bounce+1))
                    fi
                fi
            done

            # Check whois if it is an domain
            whois=$(whois $target)
            if [ $type = "domain" ];then
                whoisdata=()
                whoislist=("registrar:" "contact:" "website:" "nserver:" "address:" "key1-algo:" "Organization" "OrgName" "OrgId")
                for whoisgetinfo in ${whoislist[@]};do
                    checkwhois=$(echo "$whois"| grep -E "$whoisgetinfo" | sort -u)
                    if [[ $(echo "$checkwhois" | wc -l) > 1 ]];then
                        while IFS= read -r reformatwhois;do
                            whoisdata+=("\n   - $reformatwhois")
                        done <<< "$checkwhois"
                    else
                        if [[ "$checkwhois" != "" ]];then
                            whoisdata+=("\n   - $checkwhois")
                        fi
                    fi
                done
                if [ -z "$whoisdata" ];then
                    whoisdata+=("NO INFOS")
                fi
            else
                whoisdata+=("NO INFOS")
            fi

            # Check nmap results (first 1000 ports only)
            # Thanks to leonjza/awesome-nmap-grep project
            services=()
            nmap=$(nmap -v --reason -sV -oG - $target | egrep -v "^#|Status: Up" | cut -d' ' -f2,4- | \
            sed -n -e 's/Ignored.*//p'  | \
            awk '{print "   - Ports: " NF-1; $1=""; for(i=2; i<=NF; i++) { a=a" "$i; }; split(a,s,","); for(e in s) { split(s[e],v,"/"); printf "   - %-8s %s/%-7s %s\n" , v[2], v[3], v[1], v[5]}; a="" }')

            # Echo results
            echo "-> Status : $status"
            echo "-> Ping : $ping"
            if [ -z "$dns" ];then
                dns="ERROR"
                echo "-> DNS : $dns"
            else
                echo "-> DNS :"
                numdns=1
                echo "$dns" | while IFS= read -r line ; do echo "   $((numdns++)). $line"  ; done
            fi
            echo -e "-> Traceroute : ${hops[@]}"
            echo -e "-> Informations : ${whoisdata[@]}"
            if ! [ -z "$nmap" ];then
                echo -e "-> Nmap : \n$nmap"
            fi
        else
            validity
        fi
    else
        usage
    fi
else
    usage
fi
