import socket
import ssl
from argparse import ArgumentParser
from enum import Enum

import requests
from requests.exceptions import ConnectionError, ReadTimeout
from scapy.config import conf
from scapy.layers.inet import IP, TCP
from scapy.main import load_layer
from scapy.sendrecv import sr1, send


class PortStatus(Enum):
    CLOSED = 0
    OPEN = 1
    FILTERED = 2
    OPEN_OR_FILTERED = 3


class Synprobe:
    def __init__(self, ports_list: str, target_ip: str) -> None:
        self.target_ip = target_ip[0]
        self.portsList = []
        if ports_list is not None:
            ports_list_split = ports_list[0].split('-')
            self.firstPort = int(ports_list_split[0])
            if len(ports_list_split) == 2:
                self.lastPort = int(ports_list_split[1])
            else:
                self.lastPort = self.firstPort
            for port in range(self.firstPort, self.lastPort + 1, 1):
                self.portsList.append(port)
        else:
            self.portsList = [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]
            print(f'PortsList input not provided, scanning on standard ports {self.portsList}')

    def syn_scanning(self, target_port) -> PortStatus:
        print(f'Syn Scanning {target_port}')
        ip = IP(dst=self.target_ip)
        syn_packet = TCP(sport=1500, dport=target_port, flags="S", seq=100)
        synack_packet = sr1(ip / syn_packet)
        if synack_packet is None:
            return PortStatus.OPEN_OR_FILTERED
        elif 'S' in synack_packet[TCP].flags and 'A' in synack_packet[TCP].flags:
            rst_packet = TCP(sport=syn_packet.sport, dport=target_port, flags="R", seq=synack_packet[TCP].ack)
            send(ip / rst_packet)
            return PortStatus.OPEN
        elif 'R' in synack_packet[TCP].flags:
            return PortStatus.CLOSED

    def check_tcp_server_initiated(self, target_port):
        ip = IP(dst=self.target_ip)
        syn_packet = TCP(sport=1600, dport=target_port, flags="S", seq=200)
        synack_packet = sr1(ip / syn_packet)
        ack_packet = TCP(sport=1600, dport=target_port, flags="A", ack=synack_packet[TCP].seq + 1,
                         seq=synack_packet[TCP].ack)
        server_response_packet = sr1(ip / ack_packet, timeout=2)
        if server_response_packet is not None:
            server_response_payload = bytes(server_response_packet[TCP].payload)
            if len(server_response_payload) > 1024:
                print(f'TCP Server Initiated Response : {bytes(server_response_packet[TCP].payload)[:1024]}')
            else:
                print(f'TCP Server Initiated Response : {bytes(server_response_packet[TCP].payload)}')
            rst_packet = TCP(sport=syn_packet.sport, dport=target_port, flags="R", seq=server_response_packet[TCP].ack)
            send(ip / rst_packet)
            return True
        else:
            return False

    def check_http_server(self, target_port):
        # ip = IP(dst=self.target_ip)
        # syn_packet = TCP(sport=1600, dport=target_port, flags="S", seq=200)
        # synack_packet = sr1(ip / syn_packet)
        # ack_packet = TCP(sport=1600, dport=target_port, flags="A", ack=synack_packet[TCP].seq + 1,
        #                  seq=synack_packet[TCP].ack)
        # sr1(ip / ack_packet, timeout=2)
        # http_get_packet = TCP(sport=1600, dport=target_port, flags="P", seq=ack_packet[TCP].seq,
        #                       ack=synack_packet[TCP].seq + 2)
        # http_get_payload = Raw('GET / HTTP/1.1\r\nHost: {}\r\n\r\n'.format(self.target_ip))
        # server_response = sr1(ip / http_get_packet / http_get_payload, timeout=10)
        # if server_response:
        #     print(server_response.show())
        # else:
        #     print("No response to HTTP GET request.")
        url = f"http://{self.target_ip}:{target_port}"
        try:
            response = requests.get(url, timeout=4)
            if len(response.text) > 1024:
                print(f'{response.text[:1024]}')
            else:
                print(f'{response.text}')
            return True
        except (ConnectionError, ReadTimeout):
            return False

    def check_https_server(self, target_port):
        url = f"https://{self.target_ip}:{target_port}"
        try:
            response = requests.get(url, timeout=4)
            if len(response.text) > 1024:
                print(f'{response.text[:1024]}')
            else:
                print(f'{response.text}')
            return True
        except ConnectionError:
            return False

    def check_tls_server(self, target_port):
        context = ssl.create_default_context()
        with socket.create_connection((self.target_ip, 443)) as client:
            with context.wrap_socket(client, server_hostname=self.target_ip) as tls:
                tls.sendall(b'Hello, world')
                print('Sent Hello World')

    def scan_port(self, target_port):
        # identify if the port is open or not, if it is closed, then print that the port is closed and exit
        port_status = self.syn_scanning(target_port)
        print(f'Port {target_port} Status {port_status}')
        if port_status == PortStatus.OPEN:
            # print(f'TCP Server Initiated : {self.check_tcp_server_initiated(target_port)}')
            # print(f'HTTP Server : {self.check_http_server(target_port)}')
            # print(f'HTTPS Server : {self.check_https_server(target_port)}')
            print(f'TLS_Server Check{self.check_tls_server(target_port)}')

        # Check for server initiated protocols
        # attempt to connect to the port, with timeout of 3 s.
        # if timeout => move to below section to do active probing
        # else {
        # 	//print the 1024 bytes of the response.
        # 	return
        # }

        # Check for client-initiated portocols

        # check if the open port is TCP server-initiated (server banner was immediately returned over TCP)
        # check if the open port is TLS server-initiated (server banner was immediately returned over TLS)
        # check if the open port is HTTP server (GET request over TCP successfully elicited a response)
        # check if the open port is HTTPS server (GET request over TLS successfully elicited a response)
        # check if the open port is Generic TCP server (Generic lines over TCP may or may not elicit a response)
        # check if the open port is Generic TLS server (Generic lines over TLS may or may not elicit a response)

    def start(self):
        conf.verb = 0  # Suppress Scapy output to keep output clean
        if self.target_ip is None:
            print('Target IP not provided, it is a mandatory input. Check -h for help. Exiting')
        else:
            for port in self.portsList:
                self.scan_port(port)


if __name__ == '__main__':
    load_layer('tls')
    parser = ArgumentParser(prog='Synprobe',
                            description='Simple packet sniffer for HTTP and TLS traffic',
                            epilog="You can choose either one of -i or -r options. If both are not specified, "
                                   "this program will start sniffing on the default interface"
                                   "For more help contact Ameya Zope")

    parser.add_argument('-p', '--ports', dest='portsList', nargs=1, type=str, action='store', default=None,
                        help='The range of ports to be scanned (just a single number for one port, or a port range in '
                             'the form X-Y for multiple ports).')
    parser.add_argument("targetIp", nargs='*', type=str, action="store", default=None,
                        help='This is the IP address of a single host to be scanned')
    args = parser.parse_args()

    synProbe = Synprobe(args.portsList, args.targetIp)
    synProbe.start()
