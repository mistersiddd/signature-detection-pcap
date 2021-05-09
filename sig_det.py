import re
from collections import defaultdict
from scapy.all import *
import sys 
import json

import datetime

def main():
    data = str(sys.argv[1])
    # data = 'modbusdeteect.pcap'
    global name 
    name = str(data)
    pcap_data = rdpcap(data)
    sessions = pcap_data.sessions()
    port_map = []
    flag_1=flag_3=flag_2=flag_4=0
    for session in sessions:
        for packet in sessions[session]:     
            try:
                str_payload= re.escape((str(bytes(packet[TCP].payload))))
                signature1_re= re.search(r"\\\\...\\\\...\\\\x00\\\\x00\\\\x06\\\\x01", str_payload)
                signature2_re= re.search(r"\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x10\\\\x01\\\\x01\\\\r", str_payload)
                signature3_re= re.search(r"\\\\x00\\\\x00\\\\x00\\\\x03\\\\...\\\\x81\\\\x04", str_payload)
                signature4_re=re.search(r"\\\\x07Siemens", str_payload)
                if signature1_re is not None and flag_1 == 0:
                    attacker_src_prt = packet[TCP].sport
                    attacker_ip = packet[IP].src
                    victim_ip= packet[IP].dst
                    datetime_time = str(datetime.datetime.fromtimestamp(packet.time))
                    port_map.append({
                            'Port' : attacker_src_prt,
                            'attip' : attacker_ip,
                            'vtcip' : victim_ip,
                            'Time_stamp' : datetime_time,
                            'Tac' : 'Remote System Discovery',
                            'Name' : name
                        })
                    json_print(port_map)
                    flag_1=1
                elif signature2_re is not None and flag_1 == 1 and flag_2==0:
                    attacker_src_prt=packet[TCP].dport
                    attacker_ip = packet[IP].dst
                    victim_ip= packet[IP].src
                    datetime_time = str(datetime.datetime.fromtimestamp(packet.time))
                    port_map.clear()
                    port_map.append({
                            'Port' : attacker_src_prt,
                            'attip' : attacker_ip,
                            'vtcip' : victim_ip,
                            'Time_stamp' : datetime_time,
                            'Tac' : 'Modify Parameter',
                            'Name' : name
                        })
                    json_print(port_map)
                    flag_2=1
                elif signature3_re is not None and flag_3==0:               #find unitID detect
                    attacker_src_prt = packet[TCP].dport
                    attacker_ip = packet[IP].dst
                    victim_ip= packet[IP].src
                    datetime_time = str(datetime.datetime.fromtimestamp(packet.time))
                    port_map.clear()
                    port_map.append({
                            'Port' : attacker_src_prt,
                            'attip' : attacker_ip,
                            'vtcip' : victim_ip,
                            'Time_stamp' : datetime_time,
                            'Tac' : 'Remote System Discovery',
                            'Name' : name
                        })
                    json_print(port_map)
                    flag_3=1
                elif signature4_re is not None and flag_4==0:              #plcscan working
                    attacker_src_prt = packet[TCP].dport
                    attacker_ip = packet[IP].dst
                    victim_ip= packet[IP].src
                    datetime_time = str(datetime.datetime.fromtimestamp(packet.time))
                    port_map.clear()
                    port_map.append({
                            'Port' : attacker_src_prt,
                            'attip' : attacker_ip,
                            'vtcip' : victim_ip,
                            'Time_stamp' : datetime_time,
                            'Tac' : 'Remote System Information Discovery',
                            'Name' : name
                        })
                    json_print(port_map)
                    flag_4=1
            except:
                pass
def json_print(port_map):
    final_json = json.dumps(port_map, indent = 4)
    print(final_json)
if __name__=="__main__":
    main()