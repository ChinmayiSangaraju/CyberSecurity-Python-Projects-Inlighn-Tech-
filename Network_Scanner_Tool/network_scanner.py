import scapy.all as scapy
import socket
import threading
from queue import Queue
import ipaddress
import nmap

def get_os(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-O')  # -O is the flag for OS detection
        if ip in nm.all_hosts():
            if 'osmatch' in nm[ip]:
                return nm[ip]['osmatch'][0]['name']
            else:
                return 'Unknown'
        else:
            return 'Unknown'
    except Exception as e:
        return 'Scan Error'

def get_open_ports(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, '20-100')
        if ip in nm.all_hosts():
            # Check if the 'tcp' key exists and is a dictionary
            if 'tcp' in nm[ip]:
                open_ports = [port for port in nm[ip]['tcp'].keys() if nm[ip]['tcp'][port]['state'] == 'open']
                return open_ports
        return []
    except Exception as e:
        return []

def scan(ip, result_queue):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_request
    answer = scapy.srp(packet, timeout=1, verbose=False)[0]

    clients = []
    for client in answer:
        client_info = {'IP': client[1].psrc, 'MAC': client[1].hwsrc}
        try:
            hostname = socket.gethostbyaddr(client_info['IP'])[0]
            client_info['Hostname'] = hostname
        except socket.herror:
            client_info['Hostname'] = 'Unknown'
        
        # Add OS detection
        os_info = get_os(client_info['IP'])
        client_info['OS'] = os_info
        
        # New: Add port scanning
        ports_info = get_open_ports(client_info['IP'])
        client_info['Open Ports'] = ports_info
        
        clients.append(client_info)
    result_queue.put(clients)

def print_result(result):
    print('IP' + " "*18 + 'MAC' + " "*18 + 'Hostname' + " "*14 + 'OS' + " "*14 + 'Open Ports')
    print('-'*110)
    for client in result:
        ports_str = ', '.join(map(str, client['Open Ports']))
        print(f"{client['IP']}\t\t{client['MAC']}\t\t{client['Hostname']}\t\t{client['OS']}\t\t{ports_str}")

def main(cidr):
    results_queue = Queue()
    threads = []
    network = ipaddress.ip_network(cidr, strict=False)

    for ip in network.hosts():
        thread = threading.Thread(target=scan, args=(str(ip), results_queue))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    all_clients = []
    while not results_queue.empty():
        all_clients.extend(results_queue.get())
    
    print_result(all_clients)

if __name__ == '__main__':
    cidr = input("Enter network ip address: ")
    main(cidr)  