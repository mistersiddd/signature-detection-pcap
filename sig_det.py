import re
from collections import defaultdict
from scapy.all import *
import sys 

def main():
    data = str(sys.argv[1])
    pcap_data = rdpcap(data)
    sessions = pcap_data.sessions()
    port_map = defaultdict(list)
    for session in sessions:
        for packet in sessions[session]:
            try:
                str_payload = re.escape((str(bytes(packet[TCP].payload))))
                signature1_re = re.search(r"\\\\x00\\\\x00\\\\x06\\\\x01\\\\x04", str_payload)
                signature3_re= re.search(r"\\\\x81\\\\x04", str_payload)
                signature4_re=re.search(r"\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x10\\\\x01\\\\x01\\\\r", str_payload)
                signature5_re=re.search(r"\\\\x07Siemens", str_payload)
                if signature1_re is not None:
                            attacker_src_prt = packet[TCP].sport  
                            port_map["signature1"].append(attacker_src_prt)
                            if signature4_re is not None:
                                attacker_src_prt=packet[TCP].dport
                                port_map["signature4"].append(attacker_src_prt)
                elif signature3_re is not None:                 #find unitID detect
                    attacker_src_prt = packet[TCP].dport
                    port_map["signature3"].append(attacker_src_prt)
                elif type(signature5_re)!= type(None):              #plcscan working
                    attacker_src_prt = packet[TCP].dport
                    port_map["signature5"].append(attacker_src_prt)
            except:
                pass
    for key, value in port_map.items():
        for port in value: 
                packet_finder(sessions, port)
  
def packet_finder(sessions, attacker_src_prt):
    count=0
    for session in sessions:
        for packet in sessions[session]:
            try:
                if packet[TCP].sport == attacker_src_prt  or packet[TCP].dport == attacker_src_prt:
                    print (packet.show())
                    count=count+1
                    print('packet_number = ',count)
            except:
                pass

if __name__=="__main__":
    main()