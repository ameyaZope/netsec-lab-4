# Synprobe

## Testing

### TCP Server Initiated Protocol
Testing for tcp server initiated protocol was done by using ssh server built into kali
To start the ssh server on kali, run the following command
```bash
sudo service ssh start
```

### TCP Client Initiated Protocol
Testing for tcp client initiated protocol was done by ncat. To run a TCP ncat server, run the below
command
```bash
ncat -lkv -p 9090
```

### TLS Server Initiated Protocol Testing
Testing for TLS connection, where the communication is initiated by the server is done using a custom
script. Run the below commands on your terminal to run the tls server initiated protocol

```bash
# Generate the ssl cert and key required
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes 
# Run the tls server
python3 tls_server.py
```

### TLS Client Initiated Protocol Testing
Testing for TLS connection, where the communication is initiated by the client is done by using ncat.
Run the below commands on your terminal to start a TLS server using ncat
```bash
# Generate the ssl cert and key required
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes 
# Run the tls server
ncat -lkv -p 9090 --ssl --ssl-cert <path-to-ssl-cert> --ssl-key <path-to-ssl-key>
```

### HTTP Server
Testing for simple http server was done using python command. To run a simple http server, run the below

### Blocked/Filtered Port
**iptables** is the firewall for linux. By default, there are no firewall rules set on linux.  
To check the firewall rules on linux, use the below command

```bash
   sudo iptables -L
```

To simulate a filtered port or a firewall we need to add a rule to drop all incoming packets on  
a port say 9092. To add a rule to iptables to drop all tcp packets on 9092, run the below command
```bash
sudo iptables -A INPUT -p tcp --dport 9092 -j DROP
```

### Debugging Experience
When I ran my synprobe for the first time, the machine on which I ran the synprobe ended up sending  
two RST packets instead of the expected 1 RST packet that I was creating. Furthermore, if I sent out any
syn packet and recieved a syn-ack packet, the machine would automatically send one RST packet to the
machine who sent the RST packet. This effectively meant that I could not complete even a single handshake
via scapy. This was happening because of the OS kernel. Scapy bypasses the networks stack of the OS. When
scapy sends a SYN packet and the machine recieves a SYN-ACK packet, that SYN-ACK packet is sent to two
places. First, it is sent to the OS Kernel, who did not expect this SYN-ACK packet because it was
unaware of what scapy is doing. Hence it sends its own RST packet. Second, it reached the synprobe.py
python process. Now no matter what the synprobe.py process sends to the target machine, heuristic
obeservation is that the RST from the kernel always reached first, hence that connection was terminated
half-way. To avoid the kernel sending any information to the target machine, we want to avoid sending
any packets sent out by the synprobe.py process to the kernel. To do this, there are OS dependent solutions.
####  For MacOS
Use pf to drop any incoming packets to port 1500 and 1600 becuase these are the ports that
synprobe.py is using.

```bash
sudo vim /etc/pf.conf
```
Add the below line

block in proto tcp to any port {1500, 1600}

```bash
sudo pfctl -f /etc/pf.conf # To make pf use the rules that we just defined. 
sudo pfctl -e # To enable pf to perform packet filtering in case it is disabled
sudo pfctl -sr # To verify the rules set
```


#### For Linux
Use IP Tables to drop any incoming packets to port 1500 and 1600 becuase these are the ports that
synprobe.py is using. Run the below commands on the terminal of your linux machine

```bash
sudo iptables -A INPUT -p tcp --dport 1500 -j DROP
sudo iptables -A INPUT -p tcp --dport 1600 -j DROP
```