from scapy.all import *
import time
import requests
import ipaddress
import json

API_FILE = open(f'<KEYLOCATION>.txt', 'r')
API_KEY = API_FILE.readline()
API_FILE.close()


def check_if_locip(ipaddr):
    """
    Function: Verifies that an IP address is within a local subnet
    Parameters: (string) IP address
    Returns: (bool) True if within local subnet
    """
    ipaddr = ipaddress.ip_address(ipaddr)  #needs to be converted to an IP address object to check
    if ipaddr in ipaddress.ip_network('192.168.0.0/16'):
        return True
    elif ipaddr in ipaddress.ip_network('172.16.0.0/12'):
        return True
    elif ipaddr in ipaddress.ip_network('10.0.0.0/8'):
        return True
    else:
        return False


def compile_ip_list(list_dst, list_src):
    """
    Function: Combines destination and source IP address lists and deduplicates
    Parameters: (list, list) List of destination IPs, List of source IPs
    Returns: (list) Unique list of IPs
    """
    dst_set = set(list_dst)
    src_set = set(list_src)
    set_of_ips = dst_set | src_set  # Union of dst and src
    set_of_ips = {item for item in set_of_ips if not check_if_locip(item)}
    return list(set_of_ips)


def grab_ips(capture):
    """
    Function: Reads packets in a pcap and extracts the source and destination addresses
    Parameters: (pcap)
    Returns: (list, list) List of destination IPs, List of source IPs
    """
    dest_ips = []
    src_ips = []
    capture = rdpcap(capture)  #can use PcapReader() if dealing with larger pcaps
    for pack in capture:
        if not pack.haslayer(IP):
            continue
        else:
            dest_ips.append(pack[IP].dst)
            src_ips.append(pack[IP].src)
    return dest_ips, src_ips


def submit_ips(list_of_ips):
    """
    Function: Submits IP addresses to virustotal endpoint
    Parameters: (list) List of IP addresses to submit
    Returns: (None) Creates JSON file for each IP submitted based on the response
    """
    ip = list_of_ips[5]  #testing one ip
    ip = ip.replace('.','')
    #one off ip submission
    r = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}', headers={"x-apikey": API_KEY})
    with open('resources/output/response.json', 'w') as resp:
        resp.write(r.text) #change this so it uses json object
    #submit list of ips
    """
    for ip in list_of_ips:
        r=requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}', headers={"x-apikey":api_key})
        ip = ip.replace('.','')
        with open(f'resources/output/response{ip}.json','w') as resp:
            resp.write(r.text)
    """


#main
if __name__ == "__main__":
    start = time.time()
    dst, src = grab_ips(f'resources/pcaps/normaltraffic.pcap')
    ips_list = compile_ip_list(dst, src)
    print(ips_list)
    #submit_ips(ips_list)
    print('%s seconds to run' % (time.time() - start))
