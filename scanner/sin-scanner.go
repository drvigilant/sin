package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Data structures ────────────────────────────────────────────────────────

type Device struct {
	IPAddress    string         `json:"ip_address"`
	Status       string         `json:"status"`
	MACAddress   string         `json:"mac_address"`
	Hostname     string         `json:"hostname"`
	Manufacturer string         `json:"manufacturer"`
	Vendor       string         `json:"vendor"`
	OSFamily     string         `json:"os_family"`
	DeviceType   string         `json:"device_type"`
	OpenPorts    []int          `json:"open_ports"`
	Services     map[string]string `json:"services"`
	ProtocolHints []string      `json:"protocol_hints"`
	Vulnerabilities []interface{} `json:"vulnerabilities"`
	LastSeen     string         `json:"last_seen"`
	ScanMethod   string         `json:"scan_method"`
}

// ── Port → service name ────────────────────────────────────────────────────

var portServices = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	80:    "HTTP",
	443:   "HTTPS",
	554:   "RTSP",
	1883:  "MQTT",
	1900:  "UPnP/SSDP",
	4840:  "OPC-UA",
	5683:  "CoAP",
	8000:  "HTTP-Hikvision",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	8554:  "RTSP-Alt",
	8883:  "MQTT-TLS",
	8888:  "HTTP-Alt2",
	9100:  "JetDirect",
	37777: "Dahua-SDK",
	34567: "DVR-Web",
	47808: "BACnet",
	502:   "Modbus",
}

// IoT ports to scan
var iotPorts = []int{
	80, 443, 554, 8554, 8080, 8888, 8000,
	37777, 34567, 1883, 8883, 5683, 1900,
	502, 47808, 21, 22, 23, 8443,
}

// ── OUI table (top CCTV/IoT vendors) ─────────────────────────────────────

var ouiTable = map[string]string{
	"C8F742": "Hikvision", "D8C4E9": "Hikvision", "A4143E": "Hikvision",
	"F48B32": "Hikvision", "BC0F9A": "Hikvision", "8C54AF": "Hikvision",
	"B46B44": "Hikvision", "54B5E5": "Hikvision",
	"E0987B": "Dahua", "3C1A57": "Dahua", "704DB7": "Dahua",
	"907040": "Dahua", "90D7EB": "Dahua",
	"ACCC8E": "Axis", "00408C": "Axis", "B8A44E": "Axis",
	"D4E0B0": "Uniview", "F40226": "Uniview",
	"000AEB": "Hanwha", "34E6AD": "Hanwha",
	"000016": "Vivotek", "00032F": "Vivotek",
	"4C5E0C": "MikroTik", "D4CA6D": "MikroTik", "E4A7A0": "MikroTik",
	"B8690E": "MikroTik", "48A98A": "MikroTik",
	"788A20": "Ubiquiti", "DCF21D": "Ubiquiti", "E063DA": "Ubiquiti",
	"F09FC2": "Ubiquiti", "18E829": "Ubiquiti",
	"B0487A": "TP-Link", "F81A67": "TP-Link", "A42BB0": "TP-Link",
	"1C7EE5": "D-Link", "28107B": "D-Link",
	"A040A0": "NETGEAR", "C03F0E": "NETGEAR",
	"EC7176": "Reolink", "DCEF09": "Amcrest",
	"B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi",
}

func lookupOUI(mac string) string {
	clean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(mac, ":", ""), "-", ""))
	if len(clean) < 6 {
		return "Unknown"
	}
	oui := clean[:6]
	if vendor, ok := ouiTable[oui]; ok {
		return vendor
	}
	return "Unknown"
}

// ── Host discovery (ICMP ping) ────────────────────────────────────────────

func isAlive(ip string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip)
	return cmd.Run() == nil
}

// ── Port scanning ─────────────────────────────────────────────────────────

func scanPorts(ip string, ports []int, timeout time.Duration) []int {
	var mu sync.Mutex
	var open []int
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return open
}

// ── Banner grabbing ───────────────────────────────────────────────────────

func grabHTTPBanner(ip string, port int) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", ip)
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	for _, line := range strings.Split(resp, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(line[7:])
		}
	}
	return ""
}

func grabTCPBanner(ip string, port int) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}

// ── MAC resolution via ARP ────────────────────────────────────────────────

func getMACFromARP(ip string) string {
	// Read /proc/net/arp
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return "Unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == ip {
			mac := fields[3]
			if mac != "00:00:00:00:00:00" {
				return strings.ToUpper(mac)
			}
		}
	}
	return "Unknown"
}

// ── Hostname resolution ───────────────────────────────────────────────────

func resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return "Unknown"
	}
	return strings.TrimSuffix(names[0], ".")
}

// ── Device classification ─────────────────────────────────────────────────

func classifyDevice(ports []int, vendor string, httpBanner string) (string, string) {
	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}

	iotScore := 0
	if portSet[554] || portSet[8554] { iotScore += 3 }
	if portSet[37777] || portSet[34567] { iotScore += 3 }
	if portSet[8000] { iotScore += 2 }
	if portSet[1883] || portSet[5683] { iotScore += 2 }

	banner := strings.ToLower(httpBanner)
	vendorLow := strings.ToLower(vendor)

	camVendors := []string{"hikvision", "dahua", "axis", "vivotek", "hanwha", "uniview", "reolink", "amcrest"}
	for _, v := range camVendors {
		if strings.Contains(vendorLow, v) || strings.Contains(banner, v) {
			iotScore += 5
		}
	}

	if strings.Contains(banner, "camera") || strings.Contains(banner, "dvr") ||
		strings.Contains(banner, "nvr") || strings.Contains(banner, "ipc") {
		iotScore += 3
	}

	osFamily := "Embedded Linux"
	deviceType := "unknown"

	if portSet[445] || portSet[3389] {
		return "Windows", "workstation"
	}

	if iotScore >= 5 {
		deviceType = "camera"
	} else if portSet[37777] || portSet[34567] {
		deviceType = "nvr_dvr"
	} else if iotScore >= 2 {
		deviceType = "iot"
	} else if portSet[22] && !portSet[554] && !portSet[80] {
		return "Linux / Server", "server"
	}

	if strings.Contains(vendorLow, "mikrotik") {
		osFamily = "RouterOS"
		deviceType = "router"
	} else if strings.Contains(vendorLow, "ubiquiti") {
		osFamily = "UniFi OS"
		deviceType = "router"
	}

	return osFamily, deviceType
}

// ── Single host full scan ─────────────────────────────────────────────────

func scanHost(ip string) *Device {
	// Ping first
	if !isAlive(ip) {
		return nil
	}

	// Port scan with short timeout
	openPorts := scanPorts(ip, iotPorts, 1*time.Second)
	if len(openPorts) == 0 {
		return nil
	}

	// Drop pure Windows/PC devices
	portSet := make(map[int]bool)
	for _, p := range openPorts {
		portSet[p] = true
	}
	if (portSet[445] || portSet[3389]) && !portSet[554] && !portSet[8000] && !portSet[37777] {
		return nil
	}
	// Drop SSH-only
	if len(openPorts) == 1 && portSet[22] {
		return nil
	}

	// MAC + vendor
	mac := getMACFromARP(ip)
	vendor := lookupOUI(mac)

	// Hostname
	hostname := resolveHostname(ip)

	// HTTP banner
	httpBanner := ""
	for _, p := range []int{80, 8080, 8000, 8888} {
		if portSet[p] {
			httpBanner = grabHTTPBanner(ip, p)
			if httpBanner != "" {
				break
			}
		}
	}

	// If vendor unknown, try to identify from HTTP banner
	if vendor == "Unknown" && httpBanner != "" {
		bl := strings.ToLower(httpBanner)
		switch {
		case strings.Contains(bl, "hikvision"): vendor = "Hikvision"
		case strings.Contains(bl, "dahua"):     vendor = "Dahua"
		case strings.Contains(bl, "axis"):      vendor = "Axis"
		case strings.Contains(bl, "vivotek"):   vendor = "Vivotek"
		case strings.Contains(bl, "goahead"):   vendor = "GoAhead Camera"
		case strings.Contains(bl, "uc-httpd"):  vendor = "IP Camera (UC-HTTPd)"
		case strings.Contains(bl, "mikrotik"):  vendor = "MikroTik"
		case strings.Contains(bl, "ubiquiti"):  vendor = "Ubiquiti"
		}
	}

	// Classify
	osFamily, deviceType := classifyDevice(openPorts, vendor, httpBanner)

	// Build services map
	services := make(map[string]string)
	protocols := []string{}
	for _, p := range openPorts {
		svc, ok := portServices[p]
		if !ok {
			svc = fmt.Sprintf("TCP/%d", p)
		}
		services[strconv.Itoa(p)] = svc
		protocols = append(protocols, svc)
	}

	if httpBanner != "" && services["80"] != "" {
		services["80"] = "HTTP (" + httpBanner + ")"
	}

	return &Device{
		IPAddress:     ip,
		Status:        "online",
		MACAddress:    mac,
		Hostname:      hostname,
		Manufacturer:  vendor,
		Vendor:        vendor,
		OSFamily:      osFamily,
		DeviceType:    deviceType,
		OpenPorts:     openPorts,
		Services:      services,
		ProtocolHints: protocols,
		Vulnerabilities: []interface{}{},
		LastSeen:      time.Now().UTC().Format(time.RFC3339),
		ScanMethod:    "go-scanner",
	}
}

// ── Main ──────────────────────────────────────────────────────────────────

func main() {
	subnet := "192.168.30"
	if len(os.Args) > 1 {
		subnet = os.Args[1]
	}

	// Generate all IPs in the /24
	var ips []string
	for i := 1; i <= 254; i++ {
		ips = append(ips, fmt.Sprintf("%s.%d", subnet, i))
	}

	var mu sync.Mutex
	var devices []*Device
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100) // 100 concurrent hosts

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			device := scanHost(ip)
			if device != nil {
				mu.Lock()
				devices = append(devices, device)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()

	// Output JSON to stdout — Python reads this
	out, _ := json.Marshal(devices)
	fmt.Println(string(out))
}
