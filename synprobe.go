package main

import (
	"flag"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	snapshotLen int32         = 1024
	promiscuous bool          = false
	timeout     time.Duration = 30 * time.Second
)

func synScanning(destIpStr string, dstPort int) {

	device := findNetworkDevice()

	handle, err := pcap.OpenLive(device.Name, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// destination ip
	dstIp := net.ParseIP(destIpStr)
	if dstIp == nil {
		log.Printf("non-ip destIpStr found: %q\n", destIpStr)
	}
	dstIp = dstIp.To4()
	if dstIp == nil {
		log.Printf("non-ip destIpStr found: %q\n", destIpStr)
	}

	tcp := layers.TCP{
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(&layers.IPv4{DstIP: dstIp})

	// Prepare the IP layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		DstIP:    dstIp,
		Protocol: layers.IPProtocolTCP,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	gopacket.SerializeLayers(buffer, options, &ip, &tcp, gopacket.Payload([]byte{}))

	// Send the packet
	errWritePacket := handle.WritePacketData(buffer.Bytes())
	if errWritePacket != nil {
		log.Fatalf("[synScanning] %v", errWritePacket)
	}

	log.Printf("dstIp=%v tcpPacket=%v", dstIp, tcp)
}

func scanPort(dstIpStr string, port int) {
	//tcp-syn scanning
	//identify if the port is open or not, if it is closed, then print that the port is closed and exit
	synScanning(dstIpStr, port)
	/*
		Check for server initiated protocols
		attempt to connect to the port, with timeout of 3 s.
		if timeout => move to below section to do active probing
		else {
			//print the 1024 bytes of the response.
			return
		}
	*/

	/*
		Check for client-initiated portocols
	*/

	check if the open port is TCP server-initiated (server banner was immediately returned over TCP)

	check if the open port is TLS server-initiated (server banner was immediately returned over TLS)

	check if the open port is HTTP server (GET request over TCP successfully elicited a response)

	check if the open port is HTTPS server (GET request over TLS successfully elicited a response)

	check if the open port is Generic TCP server (Generic lines over TCP may or may not elicit a response)

	check if the open port is Generic TLS server (Generic lines over TLS may or may not elicit a response)

}

func findNetworkDevice() pcap.Interface {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Select a device (Make sure to replace with your actual interface)
	log.Printf("Device Found = %v", devices[0].Name)
	return devices[0]
}

func main() {
	portRangeInput := flag.String("p", "0", "The range of ports to be scanned (just a single number for one port, or a port range in the form X-Y for multiple ports).")
	portRange := []int{21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080}
	flag.Parse()
	if *portRangeInput == "0" {
		log.Printf("Port Range not provided, scanning default ports")
	} else {
		firstPort, errFirstPort := strconv.ParseInt(strings.Split(*portRangeInput, "-")[0], 10, 0)
		if errFirstPort != nil {
			log.Fatalf("First Port is not a valid port Number: %v", errFirstPort)
		}
		secondPort, errSecondPort := strconv.ParseInt(strings.Split(*portRangeInput, "-")[1], 10, 0)
		if errSecondPort != nil {
			log.Fatalf("Second Port is not a valid port Number: %v", errSecondPort)
		}
		portRange = nil
		for i := firstPort; i <= secondPort; i++ {
			portRange = append(portRange, int(i))
		}
	}

	args := flag.Args()

	if len(args) < 1 {
		log.Fatalf("No target IP provided")
	}

	dstIp := args[0]
	log.Printf("Target IP Address: %s", dstIp)

	for i := 0; i < len(portRange); i++ {
		log.Printf("Scanning port %d", portRange[i])
		scanPort(dstIp, portRange[i])
	}
}
