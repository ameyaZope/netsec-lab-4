import socket
import ssl
from argparse import ArgumentParser
from enum import Enum

import hexdump
import requests
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
        print(f'Syn Scanning host={self.target_ip} port={target_port}')
        ip = IP(dst=self.target_ip)
        syn_packet = TCP(sport=1500, dport=target_port, flags="S", seq=100)
        synack_packet = sr1(ip / syn_packet, timeout=3)
        if synack_packet is None:
            return PortStatus.OPEN_OR_FILTERED
        elif 'S' in synack_packet[TCP].flags and 'A' in synack_packet[TCP].flags:
            rst_packet = TCP(sport=syn_packet.sport, dport=target_port, flags="R", seq=synack_packet[TCP].ack)
            send(ip / rst_packet)
            return PortStatus.OPEN
        elif 'R' in synack_packet[TCP].flags:
            return PortStatus.CLOSED

    def check_tcp_server_initiated(self, target_port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3.0)
                sock.connect((self.target_ip, target_port))
                return sock.recv(1024)
        except socket.timeout as err:
            return None
        except socket.error as err:
            return None

    def check_tcp_client_initiated(self, target_port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3.0)
                sock.connect((self.target_ip, target_port))
                try:
                    data = sock.recv(1024)
                    if data is not None:
                        return None
                except socket.timeout as err:
                    pass
                sock.sendall(b'GET / HTTP/1.0\r\n\r\n')
                return sock.recv(1024)
        except socket.timeout as err:
            return None
        except socket.error as err:
            return None

    def check_generic_tcp_server(self, target_port):
        generic_tcp_server = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3.0)
                sock.connect((self.target_ip, target_port))
                generic_tcp_server = ""
                sock.sendall(b'\r\n\r\n\r\n')
                return sock.recv(1024)
        except socket.timeout as err:
            if generic_tcp_server is not None:
                return generic_tcp_server.encode()
            else:
                return None
        except socket.error as err:
            if generic_tcp_server is not None:
                return generic_tcp_server.encode()
            else:
                return None

    def check_tls_server_initiated(self, target_port):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target_ip, target_port)) as client:
                client.settimeout(3.0)
                with context.wrap_socket(client, server_hostname=self.target_ip) as tls:
                    return tls.recv(1024)
        except socket.timeout as err:
            return None
        except socket.error as err:
            return None

    def check_tls_client_initiated(self, target_port):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target_ip, target_port)) as client:
                client.settimeout(3.0)
                with context.wrap_socket(client, server_hostname=self.target_ip) as tls:
                    try:
                        data = tls.recv(1024)
                        if data is not None:
                            return None
                    except socket.timeout as err:
                        pass
                    tls.send(b'GET / HTTP/1.0\r\n\r\n')
                    return tls.recv(1024)
        except socket.timeout as err:
            return None
        except socket.error as err:
            return None

    def check_generic_tls_server(self, target_port):
        generic_tls_server = None
        try:
            context = ssl.create_default_context()
            context.load_verify_locations(cafile='./cert.pem')
            with socket.create_connection((self.target_ip, target_port)) as client:
                client.settimeout(3.0)
                with context.wrap_socket(client, server_hostname=self.target_ip) as tls:
                    generic_tls_server = ""
                    tls.sendall(b'\r\n\r\n\r\n\r\n')
                    return tls.recv(1024)
        except socket.timeout as err:
            if generic_tls_server is not None:
                return generic_tls_server.encode()
            else:
                return None
        except socket.error as err:
            if generic_tls_server is not None:
                return generic_tls_server.encode()
            else:
                return None

    def check_http_server(self, target_port):
        output = None
        try:
            response = requests.get(f'http://{self.target_ip}:{target_port}', timeout=3)

            output = ""
            output += f"URL: {response.url}\n"
            output += "Method: GET\n"
            output += f"Status Code: {response.status_code}\n"
            output += "Headers:\n"
            for header, value in response.headers.items():
                output += f"  {header}: {value}\n"
            output += "Cookies:\n"
            for name, value in response.cookies.items():
                output += f"  {name}: {value}\n"
            output += "Content:\n"
            output += response.text + "\n"
            return output[:1024].encode()
        except requests.RequestException as error:
            if output is not None:
                return output[:1024].encode()
            else:
                return None

    def check_https_server(self, target_port):
        output = None
        try:
            response = requests.get(f'https://{self.target_ip}:{target_port}', timeout=3)

            output = ""
            output += f"URL: {response.url}\n"
            output += "Method: GET\n"
            output += f"Status Code: {response.status_code}\n"
            output += "Headers:\n"
            for header, value in response.headers.items():
                output += f"  {header}: {value}\n"
            output += "Cookies:\n"
            for name, value in response.cookies.items():
                output += f"  {name}: {value}\n"
            output += "Content:\n"
            output += response.text + "\n"
            return output[:1024].encode()
        except requests.RequestException as error:
            if output is not None:
                return output[:1024].encode()
            else:
                return None

    def scan_port(self, target_port):
        # identify if the port is open or not, if it is closed, then print that the port is closed and exit
        port_status = self.syn_scanning(target_port)
        print(f'Port {target_port} Status {port_status}')
        if port_status == PortStatus.OPEN:
            https_server_check_status = self.check_https_server(target_port)
            if https_server_check_status is not None:
                print(f'HTTPS Server Detected \nResponse:')
                hexdump.hexdump(https_server_check_status)

            tls_server_initiated_check_status = self.check_tls_server_initiated(target_port)
            if tls_server_initiated_check_status is not None:
                print(f'TLS Server Initiated Protocol Detected \nResponse:')
                hexdump.hexdump(tls_server_initiated_check_status)
                return

            tls_client_initiated_check_status = self.check_tls_client_initiated((target_port))
            if tls_client_initiated_check_status is not None:
                print(f'TLS Client Initiated Protocol Detected \nResponse:')
                hexdump.hexdump(tls_client_initiated_check_status)
                return

            tls_generic_server_check_status = self.check_generic_tls_server(target_port)
            if tls_generic_server_check_status is not None:
                print(f'TLS Generic Server Detected \nResponse:')
                {hexdump.hexdump(tls_generic_server_check_status)}
                return

            http_server_check_status = self.check_http_server(target_port)
            if http_server_check_status is not None:
                print(f'HTTP Server Detected \nResponse:')
                hexdump.hexdump(http_server_check_status)
                return

            tcp_server_initiated_check_status = self.check_tcp_server_initiated(target_port)
            if tcp_server_initiated_check_status is not None:
                print(f'TCP Server Initiated Protocol Detected \nResponse: ')
                hexdump.hexdump(tcp_server_initiated_check_status)
                return

            tcp_client_initiated_check_status = self.check_tcp_client_initiated(target_port)
            if tcp_client_initiated_check_status is not None:
                print(f'TCP Client Initiated Protocol Detected \nResponse:')
                hexdump.hexdump(tcp_client_initiated_check_status)
                return

            tcp_generic_server_check_status = self.check_generic_tcp_server(target_port)
            if tcp_generic_server_check_status is not None:
                print(f'TCP Generic Server Detected \nResponse:')
                hexdump.hexdump(tcp_generic_server_check_status)
                return

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
