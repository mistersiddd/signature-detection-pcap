import re
from scapy.all import *
import sys 
import json
import datetime
from elasticsearch import Elasticsearch
import paho.mqtt.publish as publish

def main():
    data = str(sys.argv[1])
    global name 
    name = str(data)
    pcap_data = rdpcap(data)
    sessions = pcap_data.sessions()
    attack_info = []
    flag_RSD=flag_MP=flag_RSD_uid=flag_RSID=0
    es = Elasticsearch(
    ['localhost'],
    port=9200)
    i=0
    for session in sessions:
        for packet in sessions[session]:     
            try:
                str_payload= re.escape((str(bytes(packet[TCP].payload))))
                RSD_signature= re.search(r"\\\\...\\\\...\\\\x00\\\\x00\\\\x06\\\\x01", str_payload)
                MP_signature= re.search(r"\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x10\\\\x01\\\\x01\\\\r", str_payload)
                RSD_uid_signature= re.search(r"\\\\x00\\\\x00\\\\x00\\\\x03\\\\...\\\\x81\\\\x04", str_payload)
                RSID_signature=re.search(r"\\\\x07Siemens", str_payload)
                if RSD_signature is not None and flag_RSD == 0:             
                    attacker_src_prt = packet[TCP].sport
                    attacker_ip = packet[IP].src
                    victim_ip= packet[IP].dst
                    datetime_time = str(datetime.datetime.fromtimestamp(packet.time))
                    attack_info.append({
                            'Port' : attacker_src_prt,
                            'SrcIP' : attacker_ip,
                            'DestIP' : victim_ip,
                            'TimeStamp' : datetime_time,
                            'Technique' : 'Remote System Discovery',
                            'Tactics' : 'Discovery',
                            'Log' : name
                        })
                    i+=1
                    json_print(attack_info,es)
                    flag_RSD=1
                elif MP_signature is not None and flag_RSD == 1 and flag_MP==0:
                    attacker_src_prt=packet[TCP].dport
                    attacker_ip = packet[IP].dst
                    victim_ip= packet[IP].src
                    datetime_time = str(datetime.datetime.fromtimestamp(packet.time))
                    attack_info.clear()
                    attack_info.append({
                            'Port' : attacker_src_prt,
                            'SrcIP' : attacker_ip,
                            'DestIP' : victim_ip,
                            'TimeStamp' : datetime_time,
                            'Technique' : 'Modify Parameter',
                            'Tactics' : 'Impair Process Control',
                            'Log' : name
                        })
                    i+=1
                    json_print(attack_info,es)
                    flag_MP=1
                elif RSD_uid_signature is not None and flag_RSD_uid==0:               #find unitID detect
                    attacker_src_prt = packet[TCP].dport
                    attacker_ip = packet[IP].dst
                    victim_ip= packet[IP].src
                    datetime_time = str(datetime.datetime.fromtimestamp(packet.time))
                    attack_info.clear()
                    attack_info.append({
                            'Port' : attacker_src_prt,
                            'SrcIP' : attacker_ip,
                            'DestIP' : victim_ip,
                            'TimeStamp' : datetime_time,
                            'Technique' : 'Remote System Discovery',
                            'Tactics' : 'Discovery',
                            'Log' : name
                        })
                    i+=1
                    json_print(attack_info,es)
                    flag_RSD_uid=1
                elif RSID_signature is not None and flag_RSID==0:              #plcscan working
                    attacker_src_prt = packet[TCP].dport
                    attacker_ip = packet[IP].dst
                    victim_ip= packet[IP].src
                    datetime_time = str(datetime.datetime.fromtimestamp(packet.time))
                    attack_info.clear()
                    attack_info.append({
                            'Port' : attacker_src_prt,
                            'SrcIP' : attacker_ip,
                            'DestIP' : victim_ip,
                            'TimeStamp' : datetime_time,
                            'Technique' : 'Remote System Information Discovery',
                            'Tactics' : 'Discovery',
                            'Log' : name
                        })
                    i+=1
                    json_print(attack_info,es)
                    flag_RSID=1
            except:
                pass
def json_print(attack_info,es):
    final_json = json.dumps(attack_info, indent = 4)
    y=json.loads(final_json)
    res = es.index(index='attack', body=y[0])
    publish.single("ics", str(y), hostname="test.mosquitto.org")

if __name__=="__main__":
    main()