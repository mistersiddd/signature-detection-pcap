from scapy.all import *
import time;
import re; 
import os;
data = "plcscan.pcap"
a = rdpcap(data)
sessions = a.sessions()
flag=0
attacker_ip = ""
signature1 = "\\x00\\x00\\x00\\x00\\x06\\x01\\x04\\x00\\x01\\x00\\x00" #modbusdetect
signature2 = "\\x00\\x00\\x00\\x00\\x03\\x01\\x84\\x03"                #modbusdetect
#signature3= "\\x00\\x9c\\x00\\x00\\x00\\x03\\x9b\\x81\\x04"    
signature4= "\\x00\\x00\\x00\\x00\\x00\\x06\\x01"
counter=0

def packet_finder():
    count=0
    for session in sessions:
        for packet in sessions[session]:
            try:
                if packet[IP].src == attacker_ip  or packet[IP].dst == attacker_ip:
                    print (packet.show())
                    count=count+1
                    print('packet_number = ',count)
            except:
                pass

for session in sessions:
    for packet in sessions[session]:
        try:
            str_payload = re.escape((str(bytes(packet[TCP].payload))))
            signature3 = re.search(r"\\\\x81\\\\x04", str_payload)
            signature4_re=re.search(r"\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x06\\\\x01\\\\x01\\\\x00\\\\x01", str_payload)
            signature5_re=re.search(r"\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x05\\\\x01", str_payload)
            # print(signature5_re)
            if signature1 in str(packet[TCP].payload) or signature2 in str(packet[TCP].payload) or flag==1:# detection of scanning
                if flag==0 :
                    print('Attack Detected Scanning ')
                    attacker_ip=packet[IP].dst 
                    packet_finder()
                    flag=1
                # elif flag ==1 :                                               # detecting read and writing the modbus when merged pcap
                #     if type(signature4_re) != type(None) and counter ==0:
                #         print('Attack Detected read or writing modbus ')
                #         attacker_ip=packet[IP].src
                #         # print(attacker_ip)
                #         counter=counter+1  
                #         packet_finder()
                #     # elif type(signature5_re)
            elif type(signature3)!= type(None) and flag==0:                 #find unitID detect
                attacker_ip=packet[IP].dst
                print('Attack Detected UnitID Scanning ')
                flag=1
                packet_finder()  
            elif type(signature5_re)!= type(None) and flag==0:              #plcscan
                attacker_ip=packet[IP].src
                print(attacker_ip)
                print('Attack Detected UnitID Scanning ')
                flag=1
                packet_finder() 
            elif type(signature4_re) != type(None) and counter ==0:       # detecting read and writing the modbus
                print('detected!')
                attacker_ip=packet[IP].src
                print(attacker_ip)
                # counter=counter+1  
                packet_finder()
        except:
            pass