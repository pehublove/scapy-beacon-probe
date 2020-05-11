#!/usr/bin/python env
#-*- coding:utf8 -*-

import getopt
import time
import sys,os
import threading
from scapy.all import *

iface = "wlan0"
myMac = "aa:bb:cc:aa:bb:cc"
client_addr = None

def get_rates(packet):
    rates = "\x82\x84\x0b\x16"
    esrates = "\x0c\x12\x18"

    while Dot11Elt in packet:
        packet = packet[Dot11Elt]
        if packet.ID == 1:
            rates = packet.info
        elif packet.ID == 50:
            esrates = packet.info
        packet = packet.payload

    return [rates,esrates]

def send_probe_response(packet):
    ssid = packet.info
    rates = get_rates(packet)
    channel = "\x06"

    print "\nSending probe response for "+ ssid + "to" + str(packet[Dot11].addr2)+"\n"
    cap = "ESS+privacy+short-preamble+short-slot"
    resp = RadioTap() / Dot11(addr1=packet[Dot11].addr2,addr2=myMac,addr3=myMac)/ \
           Dot11ProbeResp(timestamp=time.time(),cap=cap) / \
           Dot11Elt(ID='SSID',info=ssid) / \
           Dot11Elt(ID='Rates',info=rates[0]) / \
           Dot11Elt(ID='DSset',info=channel) / \
           Dot11Elt(ID='ESRates',info=rates[1])
    sendp(resp,iface=iface)

def handle_packet(packet):
    if packet.haslayer(Dot11ProbeReq):
        if packet.addr2[1] == '2' or packet.addr2[1] == '6' or packet.addr2[1] == 'a' or packet.addr2[1] == 'e': #判断是否为随机MAC地址
            subThread = threading.Thread(target=send_probe_response,args=(packet,))
            subThread.setDaemon(True)
            subThread.start()
            
    elif packet.haslayer(Dot11Auth):
        if client_addr and packet.addr2 == client_addr:
            print "\nReceive the real mac:"+packet.addr2+"\n"
            packet.show()
            print '*' * 20
def send_beacon(ssid):
	channel = "\x06"
	print "\nSending Beacon with "+ ssid +"\n"
	beacon_packet = RadioTap() / Dot11(subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=myMac, addr3=myMac) / \
	Dot11Beacon(cap=0x2105) / \
	Dot11Elt(ID='SSID', info=ssid) / \
	Dot11Elt(ID='Rates', info="\x0c\x12\x18\x24\x30\x48\x60\x6c") / \
	Dot11Elt(ID='DSset', info=channel)
	
	beacon_packet[Dot11Beacon].timestamp = time.time()
	sendp(beacon_packet,iface=iface)

def main():
    if len(sys.argv) < 2:
        print "usage:python proberes.py realMac"
    client_addr = sys.argv[1]
	  #create one thread,for sending Beacon packet
	  #bcThread = threading.Thread(target=send_beacon,args=(ssid,))
	  #bcThread.setDaemon(True)
	  #bcThread.start()    
    sniff(iface=iface,prn=handle_packet,store=0)
    
if __name__ == '__main__':
    main()
