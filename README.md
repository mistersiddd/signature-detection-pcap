# Signature Detection from PCAP
 
A signature based detection for ICS attacks from a pcap file. 

## To run dynamic detection
```
git clone https://github.com/mistersiddd/signature-detection-pcap.git
cd signature-detection-pcap
chmod +x dynamic.sh
sudo dynamic.sh
```
Note: Linux users change 'gtimeout' to 'timeout' in dynamic.sh

# To run detection from pcap
```
python3 signature_detection.py <FILE.pcap>
```
