#! /bin/sh
# $Id: iptables_init.sh,v 1.5 2011/05/16 12:11:37 nanard Exp $
IPTABLES=/sbin/iptables

RTPSTARTPORT=50000
RTPENDPORT=60000

#change this parameters :
EXTIF=br1
#INTIF=eth0:1

#kernel enable
echo "1" > /proc/sys/net/ipv4/ip_forward

EXTIP="`LC_ALL=C /sbin/ifconfig $EXTIF | grep 'inet ' | awk '{print $2}' | sed -e 's/.*://'`"
echo "External IP = $EXTIP"

#adding the MINIUPNPD chain for nat
$IPTABLES -t nat --flush
$IPTABLES -t filter --flush

$IPTABLES -t nat -F MINIUPNPD 
$IPTABLES -t filter -F MINIUPNPD 

$IPTABLES -t nat -X MINIUPNPD
$IPTABLES -t filter -X MINIUPNPD


#adding the MINIUPNPD chain for filter
$IPTABLES -t nat -N MINIUPNPD
$IPTABLES -t filter -N MINIUPNPD

#adding the rule to MINIUPNPD
#$IPTABLES -t nat -A PREROUTING -d $EXTIP -i $EXTIF -j MINIUPNPD
#$IPTABLES -t nat -A PREROUTING -i $EXTIF -j MINIUPNPD

$IPTABLES -A PREROUTING -t nat -i $EXTIF -p udp --dport $RTPSTARTPORT:$RTPENDPORT -j MINIUPNPD
#$IPTABLES -A PREROUTING -t nat -i $INTIF -p udp --dport $RTPSTARTPORT:$RTPENDPORT -j MINIUPNPD



#adding the rule to MINIUPNPD
#$IPTABLES -t filter -A FORWARD -i $EXTIF ! -o $EXTIF -j MINIUPNPD


$IPTABLES -t filter -A FORWARD -p udp --dport $RTPSTARTPORT:$RTPENDPORT -i $EXTIF -j MINIUPNPD
#$IPTABLES -t filter -A FORWARD -p udp --dport $RTPSTARTPORT:$RTPENDPORT -i $INTIF -j MINIUPNPD


iptables -t nat -A POSTROUTING -s '10.1.1.0/24' -o $EXTIF -j MASQUERADE
#iptables -t nat -A POSTROUTING -s '192.168.0.0/24' -o eth1 -j MASQUERADE
#iptables -t nat -A POSTROUTING -s '10.1.1.0/24' -o $INTIF -j MASQUERADE
