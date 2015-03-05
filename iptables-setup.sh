#!/bin/bash

IPT=/sbin/iptables
WAN=e1000
LAN=eth0

modprobe iptable_nat

#removing the MINIUPNPD chain for nat
$IPT -t nat -F MINIUPNPD
$IPT -t nat -D PREROUTING -i $WAN -j MINIUPNPD
$IPT -t nat -X MINIUPNPD

#removing the MINIUPNPD chain for filter
$IPT -t filter -F MINIUPNPD
$IPT -t filter -D FORWARD -i $WAN -o ! $WAN -j MINIUPNPD
$IPT -t filter -X MINIUPNPD

#adding the MINIUPNPD chain for nat
$IPT -t nat -N MINIUPNPD
#$IPT -t nat -A PREROUTING -i $WAN -j MINIUPNPD
$IPT -t nat -I PREROUTING -i $WAN -j MINIUPNPD

#adding the MINIUPNPD chain for filter
$IPT -t filter -N MINIUPNPD
#$IPT -t filter -A FORWARD -i $WAN -o ! $WAN -j MINIUPNPD
$IPT -t filter -I FORWARD -i $WAN -o ! $WAN -j MINIUPNPD
