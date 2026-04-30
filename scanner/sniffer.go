package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// AnomalySignal matches the Python PacketEngine expectation
type AnomalySignal struct {
	IP        string `json:"ip"`
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Details   string `json:"details"`
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: ./sin-sniffer <interface> (e.g., ./sin-sniffer eth0)")
	}
	iface := os.Args[1]

	// Setup UDP connection to Python Brain
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:9999")
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// Open network interface
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open %s: %v (Try running as root)", iface, err)
	}
	defer handle.Close()

	// Compile BPF filter to drop noise at the kernel level (ignore our own UDP channel)
	err = handle.SetBPFFilter("tcp or udp port not 9999")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("📡 High-Performance Go Sniffer attached to %s\n", iface)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	for packet := range packetSource.Packets() {
		// Extract IP layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		// Extract TCP layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			// Rule 1: Mirai / IoT Botnet sweep (Telnet port 23/2323)
			if tcp.SYN && !tcp.ACK && (tcp.DstPort == 23 || tcp.DstPort == 2323) {
				sendSignal(conn, ip.SrcIP.String(), "Mirai Probe", "HIGH", "Outbound Telnet SYN detected")
			}

			// Rule 2: Unencrypted Credentials (FTP/HTTP)
			if tcp.DstPort == 21 || tcp.DstPort == 80 {
				payload := packet.ApplicationLayer()
				if payload != nil {
					// Basic signature check for cleartext passwords
					if containsCleartextAuth(payload.Payload()) {
						sendSignal(conn, ip.SrcIP.String(), "Cleartext Auth", "CRITICAL", "Unencrypted credentials observed on wire")
					}
				}
			}
		}
	}
}

func containsCleartextAuth(data []byte) bool {
	payload := string(data)
	return len(payload) > 4 && (len(payload) < 200) && 
		(string(data[0:4]) == "USER" || string(data[0:4]) == "PASS" || string(data[0:13]) == "Authorization")
}

func sendSignal(conn *net.UDPConn, ip, alertType, severity, details string) {
	sig := AnomalySignal{
		IP:        ip,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Type:      alertType,
		Severity:  severity,
		Details:   details,
	}
	jsonData, _ := json.Marshal(sig)
	conn.Write(jsonData)
}
