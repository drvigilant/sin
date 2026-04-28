package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// 8899 is the secret 'ONVIF' port for many XM/Dahua devices
var targetPorts = []int{80, 443, 554, 34567, 37777, 8080, 8899}

type Device struct {
	IPAddress    string         `json:"ip_address"`
	Status       string         `json:"status"`
	DeviceType   string         `json:"device_type"`
	Manufacturer string         `json:"manufacturer"`
	Model        string         `json:"model"`
	OSFamily     string         `json:"os_family"`
	OpenPorts    []int          `json:"open_ports"`
	Banners      map[int]string `json:"banners"`
	DiscoverySrc string         `json:"discovery_method"`
}

type ScanResult struct {
	IP          string
	Port        int
	Open        bool
	Banner      string
	ProtoVendor string
	ProtoModel  string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println(`{"error": "Please provide a subnet"}`)
		os.Exit(1)
	}
	subnet := os.Args[1]

	jobs := make(chan string, 10000)
	results := make(chan ScanResult, 10000)
	var wg sync.WaitGroup

	for w := 1; w <= 100; w++ {
		wg.Add(1)
		go worker(jobs, results, &wg)
	}

	go func() {
		for i := 1; i <= 254; i++ {
			ip := fmt.Sprintf("%s.%d", subnet, i)
			for _, port := range targetPorts {
				jobs <- fmt.Sprintf("%s:%d", ip, port)
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	hostData := make(map[string]map[int]string)
	hostIntel := make(map[string]ScanResult)

	for res := range results {
		if res.Open {
			if hostData[res.IP] == nil {
				hostData[res.IP] = make(map[int]string)
			}
			hostData[res.IP][res.Port] = res.Banner

			if res.ProtoVendor != "" && res.ProtoVendor != "Unknown" {
				hostIntel[res.IP] = res
			}
		}
	}

	networkAssets := []Device{}
	for ip, portMap := range hostData {
		var ports []int
		for p := range portMap { ports = append(ports, p) }
		sort.Ints(ports)

		deviceType, vendor, model, osFam, method := ClassifyDevice(ports, portMap)

		// Check if Directed Probe gave us better intel
		intel, hasIntel := hostIntel[ip]
		if hasIntel {
			vendor = intel.ProtoVendor
			model = intel.ProtoModel
			method = "Directed ONVIF Probe"
		}

		networkAssets = append(networkAssets, Device{
			IPAddress:    ip,
			Status:       "online",
			DeviceType:   deviceType,
			Manufacturer: vendor,
			Model:        model,
			OSFamily:     osFam,
			OpenPorts:    ports,
			Banners:      portMap,
			DiscoverySrc: method,
		})
	}

	output, _ := json.MarshalIndent(networkAssets, "", "  ")
	fmt.Println(string(output))
}

func worker(jobs <-chan string, results chan<- ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for target := range jobs {
		ip, portStr, _ := net.SplitHostPort(target)
		var port int
		fmt.Sscanf(portStr, "%d", &port)

		conn, err := net.DialTimeout("tcp", target, 2500*time.Millisecond)
		if err == nil {
			banner := grabBanner(conn, ip, port)
			conn.Close()

			res := ScanResult{IP: ip, Port: port, Open: true, Banner: banner}

			// Directed probe on specific IoT management ports
			if port == 3702 || port == 8899 || port == 34567 {
				v, m := directOnvifProbe(ip, port)
				res.ProtoVendor = v
				res.ProtoModel = m
			}

			results <- res
		}
	}
}

func directOnvifProbe(ip string, port int) (string, string) {
	onvifProbe := `<?xml version="1.0" encoding="UTF-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:d="http://schemas.xmlsoap.org/ws/2004/08/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><e:Header><w:MessageID xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing">uuid:550e8400-e29b-41d4-a716-446655440000</w:MessageID><w:To xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing">urn:schemas-xmlsoap.org:ws:2004:08:discovery</w:To><w:Action xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing">http://schemas.xmlsoap.org/ws/2004/08/discovery/Probe</w:Action></e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>`
	
	// Try standard ONVIF discovery port 3702
	addr, _ := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:3702", ip))
	conn, err := net.DialUDP("udp4", nil, addr)
	if err == nil {
		defer conn.Close()
		conn.Write([]byte(onvifProbe))
		conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err == nil {
			raw := string(buf[:n])
			if strings.Contains(raw, "Xiongmai") || strings.Contains(raw, "XM") {
				return "Xiongmai", "ONVIF Smart Camera"
			}
		}
	}
	return "", ""
}

func grabBanner(conn net.Conn, ip string, port int) string {
	conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	if port == 80 || port == 8080 || port == 8899 {
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", ip)
	} else if port == 554 {
		fmt.Fprintf(conn, "OPTIONS rtsp://%s:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", ip)
	}
	reader := bufio.NewReader(conn)
	for i := 0; i < 5; i++ {
		line, _ := reader.ReadString('\n')
		if strings.HasPrefix(line, "Server:") || strings.Contains(line, "DVR") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func ClassifyDevice(ports []int, banners map[int]string) (string, string, string, string, string) {
	deviceType := "IP Camera / NVR"
	vendor := "Unknown"
	model := "Generic IoT Node"
	osFam := "Embedded Linux"
	method := "Signature Analysis"

	allBanners := strings.ToLower(fmt.Sprintf("%v", banners))
	
	// 🧠 Advanced Heuristic: The 'H264DVR' signature is unique to Xiongmai hardware
	if strings.Contains(allBanners, "h264dvr") || strings.Contains(allBanners, "dvr") {
		vendor = "Xiongmai (XM) OEM"
		model = "XM-Embedded-DVR"
		method = "Deep Banner Interrogation"
	}

	// Port 34567 is the 'Sofia' protocol - 100% Xiongmai
	for _, p := range ports {
		if p == 34567 {
			vendor = "Xiongmai (XM) OEM"
			model = "Sofia-Protocol Device"
			method = "Port-Protocol Mapping"
		}
	}

	return deviceType, vendor, model, osFam, method
}
