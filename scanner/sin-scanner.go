package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Data structures ────────────────────────────────────────────────────────

type Device struct {
	IPAddress       string            `json:"ip_address"`
	Status          string            `json:"status"`
	MACAddress      string            `json:"mac_address"`
	Hostname        string            `json:"hostname"`
	Manufacturer    string            `json:"manufacturer"`
	Vendor          string            `json:"vendor"`
	OSFamily        string            `json:"os_family"`
	DeviceType      string            `json:"device_type"`
	OpenPorts       []int             `json:"open_ports"`
	Services        map[string]string `json:"services"`
	ProtocolHints   []string          `json:"protocol_hints"`
	Vulnerabilities []interface{}     `json:"vulnerabilities"`
	LastSeen        string            `json:"last_seen"`
	ScanMethod      string            `json:"scan_method"`
	JARMHash        string            `json:"jarm_hash"`
	// ONVIF enriched fields
	Model    string `json:"model"`
	Firmware string `json:"firmware"`
	Serial   string `json:"serial_number"`
}

// ── ONVIF Probe ───────────────────────────────────────────────────────────

type ONVIFInfo struct {
	Manufacturer string
	Model        string
	Firmware     string
	Serial       string
	HardwareID   string
}

const onvifSOAP = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <soap:Header/>
  <soap:Body>
    <tds:GetDeviceInformation/>
  </soap:Body>
</soap:Envelope>`

func probeONVIF(ip string, port int) *ONVIFInfo {
	url := fmt.Sprintf("http://%s:%d/onvif/device_service", ip, port)
	if port == 443 {
		url = fmt.Sprintf("https://%s/onvif/device_service", ip)
	}

	client := &http.Client{Timeout: 4 * time.Second}
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(onvifSOAP))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/soap+xml")
	req.Header.Set("User-Agent", "SIN-Scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16384))
	if err != nil || resp.StatusCode >= 400 {
		return nil
	}

	xml := string(body)
	// If device returns HTML (login page), skip
	if strings.Contains(strings.ToLower(xml[:min(len(xml), 100)]), "<html") {
		return nil
	}

	info := &ONVIFInfo{}
	info.Manufacturer = extractXMLTag(xml, "Manufacturer")
	info.Model = extractXMLTag(xml, "Model")
	info.Firmware = extractXMLTag(xml, "FirmwareVersion")
	info.Serial = extractXMLTag(xml, "SerialNumber")
	info.HardwareID = extractXMLTag(xml, "HardwareId")

	// Only return if we got at least one useful field
	if info.Manufacturer == "" && info.Model == "" && info.Firmware == "" {
		return nil
	}
	return info
}

// extractXMLTag pulls the first inner text of a given tag name (namespace-agnostic)
func extractXMLTag(xml, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	// Also handle namespaced tags like <tds:Model>
	idx := strings.Index(xml, open)
	if idx == -1 {
		// Try namespace variants
		nIdx := strings.Index(xml, ":"+tag+">")
		if nIdx == -1 {
			return ""
		}
		// Find the opening tag start
		start := strings.LastIndex(xml[:nIdx], "<")
		if start == -1 {
			return ""
		}
		// Find content between > and </
		contentStart := strings.Index(xml[start:], ">")
		if contentStart == -1 {
			return ""
		}
		contentStart += start + 1
		contentEnd := strings.Index(xml[contentStart:], "</")
		if contentEnd == -1 {
			return ""
		}
		return strings.TrimSpace(xml[contentStart : contentStart+contentEnd])
	}
	start := idx + len(open)
	end := strings.Index(xml[start:], close)
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(xml[start : start+end])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── JARM TLS Fingerprinting ───────────────────────────────────────────────────

var jarmVendorMap = map[string]string{
	"2ad2ad0002ad2ad22c": "Hikvision Camera (cloud relay)",
	"2ad2ad0002ad2ad00c": "Hikvision NVR",
	"05d02ad2ad0002ad22": "Dahua Camera",
	"05d005d0002ad2ad22": "Dahua NVR/XVR",
	"000000000000000000": "No TLS / closed",
}

func jarmVendorLookup(fingerprint string) string {
	if len(fingerprint) < 18 {
		return ""
	}
	prefix := fingerprint[:18]
	if vendor, ok := jarmVendorMap[prefix]; ok {
		return vendor
	}
	return ""
}

type jarmCfg struct {
	ciphers [][]byte
	version []byte
	useSNI  bool
	useALPN bool
}

var jarm12Ciphers = [][]byte{
	{0xc0, 0x2b}, {0xc0, 0x2f}, {0xc0, 0x2c}, {0xc0, 0x30},
	{0xcc, 0xa9}, {0xcc, 0xa8}, {0xc0, 0x13}, {0xc0, 0x14},
	{0x00, 0x9c}, {0x00, 0x9d}, {0x00, 0x2f}, {0x00, 0x35},
	{0x00, 0xff},
}

var jarm13Ciphers = [][]byte{
	{0x13, 0x01}, {0x13, 0x02}, {0x13, 0x03},
	{0x00, 0x9c}, {0x00, 0x9d}, {0x00, 0x2f}, {0x00, 0x35},
}

func reverseCiphers(s [][]byte) [][]byte {
	r := make([][]byte, len(s))
	for i, v := range s {
		r[len(s)-1-i] = v
	}
	return r
}

func jarmProbeList() []jarmCfg {
	c12  := jarm12Ciphers
	c12r := reverseCiphers(c12)
	c13  := jarm13Ciphers
	c13r := reverseCiphers(c13)
	v12  := []byte{0x03, 0x03}
	v10  := []byte{0x03, 0x01}
	return []jarmCfg{
		{c12, v12, true, false},
		{c12r, v12, true, false},
		{c12, v12, false, false},
		{c12, v12, true, true},
		{c12r, v12, false, false},
		{c12, v10, true, false},
		{c13, v12, true, false},
		{c13r, v12, true, false},
		{c13, v12, false, false},
		{c13, v12, true, true},
	}
}

func jarmBuildClientHello(host string, cfg jarmCfg) []byte {
	var exts bytes.Buffer

	if cfg.useSNI && host != "" {
		hostB := []byte(host)
		hLen := len(hostB)
		exts.Write([]byte{0x00, 0x00})
		extLen := uint16(5 + hLen)
		exts.WriteByte(byte(extLen >> 8))
		exts.WriteByte(byte(extLen))
		listLen := uint16(3 + hLen)
		exts.WriteByte(byte(listLen >> 8))
		exts.WriteByte(byte(listLen))
		exts.WriteByte(0x00)
		exts.WriteByte(byte(hLen >> 8))
		exts.WriteByte(byte(hLen))
		exts.Write(hostB)
	}

	exts.Write([]byte{
		0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08,
		0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
	})
	exts.Write([]byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00})
	exts.Write([]byte{0x00, 0x23, 0x00, 0x00})
	exts.Write([]byte{0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00})
	exts.Write([]byte{
		0x00, 0x0d, 0x00, 0x10, 0x00, 0x0e,
		0x04, 0x01, 0x08, 0x04, 0x04, 0x03, 0x08, 0x07,
		0x08, 0x05, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01,
	})

	if cfg.useALPN {
		exts.Write([]byte{
			0x00, 0x10, 0x00, 0x0b, 0x00, 0x09, 0x08,
			'h', 't', 't', 'p', '/', '1', '.', '1',
		})
	}

	exts.Write([]byte{0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03})
	exts.Write([]byte{0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20})
	exts.Write(make([]byte, 32))

	extB := exts.Bytes()

	var body bytes.Buffer
	body.Write(cfg.version)
	body.Write(make([]byte, 32))
	body.WriteByte(0x00)
	csLen := len(cfg.ciphers) * 2
	body.WriteByte(byte(csLen >> 8))
	body.WriteByte(byte(csLen))
	for _, cs := range cfg.ciphers {
		body.Write(cs)
	}
	body.Write([]byte{0x01, 0x00})
	body.WriteByte(byte(len(extB) >> 8))
	body.WriteByte(byte(len(extB)))
	body.Write(extB)

	bodyB := body.Bytes()

	var hs bytes.Buffer
	hs.WriteByte(0x01)
	hs.WriteByte(0x00)
	hs.WriteByte(byte(len(bodyB) >> 8))
	hs.WriteByte(byte(len(bodyB)))
	hs.Write(bodyB)
	hsB := hs.Bytes()

	var rec bytes.Buffer
	rec.WriteByte(0x16)
	rec.Write([]byte{0x03, 0x01})
	rec.WriteByte(byte(len(hsB) >> 8))
	rec.WriteByte(byte(len(hsB)))
	rec.Write(hsB)
	return rec.Bytes()
}

func sendJARMProbe(host string, port int, cfg jarmCfg) (string, string) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "000", ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	pkt := jarmBuildClientHello(host, cfg)
	if _, err := conn.Write(pkt); err != nil {
		return "000", ""
	}

	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil || n < 44 {
		return "000", ""
	}
	data := buf[:n]

	if data[0] == 0x15 || data[0] != 0x16 {
		return "000", ""
	}
	if n < 9 || data[5] != 0x02 {
		return "000", ""
	}

	verIndicator := "2"
	if data[9] == 0x03 && data[10] == 0x04 {
		verIndicator = "3"
	}

	sessionIDLen := int(data[43])
	cipherOff := 44 + sessionIDLen
	if n < cipherOff+2 {
		return "000", ""
	}

	cipherByte := data[cipherOff+1]
	cipherCode := fmt.Sprintf("%02x%s", cipherByte, verIndicator)

	extOff := cipherOff + 3
	extHex := ""
	if n > extOff+2 {
		extLen := int(data[extOff])<<8 | int(data[extOff+1])
		end := extOff + 2 + extLen
		if end > n {
			end = n
		}
		extHex = fmt.Sprintf("%x", data[extOff+2:end])
	}

	return cipherCode, extHex
}

func jarmFingerprint(host string, port int) string {
	probes := jarmProbeList()
	var cipherParts, extParts []string
	for _, p := range probes {
		c, e := sendJARMProbe(host, port, p)
		cipherParts = append(cipherParts, c)
		extParts = append(extParts, e)
	}
	cipherStr := strings.Join(cipherParts, "")
	extCombined := strings.Join(extParts, ",")
	h := sha256.Sum256([]byte(extCombined))
	extHash := fmt.Sprintf("%x", h)[:32]
	return cipherStr + extHash
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
	"D46137": "Securus",
	"001233": "Securus", // Securus OUI from Swatak screenshot (d4:61:37)
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
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n\r\n", ip)
	buf := make([]byte, 8192)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	lower := strings.ToLower(resp)

	// Check Server header first
	for _, line := range strings.Split(resp, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			val := strings.TrimSpace(line[7:])
			if val != "" {
				return val
			}
		}
	}

	// Fallback: extract <title> tag dynamically
	if idx := strings.Index(lower, "<title>"); idx != -1 {
		start := idx + 7
		end := strings.Index(lower[start:], "</title>")
		if end != -1 {
			title := strings.TrimSpace(resp[start : start+end])
			title = strings.ReplaceAll(title, "\n", " ")
			title = strings.ReplaceAll(title, "\r", "")
			if len(title) > 0 && len(title) < 100 {
				return title
			}
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
	if err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	return ""
}

// ── Device classification ─────────────────────────────────────────────────

func classifyDevice(ports []int, vendor string, httpBanner string) (string, string) {
	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}

	iotScore := 0
	if portSet[554] || portSet[8554] {
		iotScore += 3
	}
	if portSet[37777] || portSet[34567] {
		iotScore += 3
	}
	if portSet[8000] {
		iotScore += 2
	}
	if portSet[1883] || portSet[5683] {
		iotScore += 2
	}

	banner := strings.ToLower(httpBanner)
	vendorLow := strings.ToLower(vendor)

	camVendors := []string{"hikvision", "dahua", "axis", "vivotek", "hanwha", "uniview", "reolink", "amcrest", "securus"}
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

	if portSet[445] || portSet[3389] || portSet[135] || portSet[139] {
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
	if !isAlive(ip) {
		return nil
	}

	openPorts := scanPorts(ip, iotPorts, 1*time.Second)
	if len(openPorts) == 0 {
		return nil
	}

	portSet := make(map[int]bool)
	for _, p := range openPorts {
		portSet[p] = true
	}

	// Drop pure Windows/PC devices by SMB/RDP ports
	if (portSet[445] || portSet[3389]) && !portSet[554] && !portSet[8000] && !portSet[37777] {
		return nil
	}

	// Drop Windows dev machines running IIS on 8000/8080 without camera ports
	httpCheck := ""
	for _, p := range []int{80, 8080, 8000} {
		if portSet[p] {
			httpCheck = strings.ToLower(grabHTTPBanner(ip, p))
			break
		}
	}
	if strings.Contains(httpCheck, "microsoft-iis") && !portSet[554] && !portSet[34567] && !portSet[37777] {
		return nil
	}

	// Drop SSH-only
	if len(openPorts) == 1 && portSet[22] {
		return nil
	}

	// MAC + vendor from OUI
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

	// Vendor from HTTP banner if OUI unknown
	if vendor == "Unknown" && httpBanner != "" {
		bl := strings.ToLower(httpBanner)
		switch {
		case strings.Contains(bl, "hikvision"):
			vendor = "Hikvision"
		case strings.Contains(bl, "dahua"):
			vendor = "Dahua"
		case strings.Contains(bl, "axis"):
			vendor = "Axis"
		case strings.Contains(bl, "vivotek"):
			vendor = "Vivotek"
		case strings.Contains(bl, "goahead"):
			vendor = "GoAhead Camera"
		case strings.Contains(bl, "uc-httpd"):
			vendor = "IP Camera (UC-HTTPd)"
		case strings.Contains(bl, "mikrotik"):
			vendor = "MikroTik"
		case strings.Contains(bl, "ubiquiti"):
			vendor = "Ubiquiti"
		case strings.Contains(bl, "securus"):
			vendor = "SECURUS"
		case strings.Contains(bl, "nbl-web"), strings.Contains(bl, "nbl"):
			vendor = "NBL"
		}
	}

	// ── ONVIF Probe ───────────────────────────────────────────────────────
	// Try port 80 first, then 443
	var onvif *ONVIFInfo
	for _, p := range []int{80, 443, 8080} {
		if portSet[p] {
			onvif = probeONVIF(ip, p)
			if onvif != nil {
				break
			}
		}
	}

	// Enrich vendor/hostname from ONVIF if still unknown
	model := ""
	firmware := ""
	serial := ""
	if onvif != nil {
		model = onvif.Model
		firmware = onvif.Firmware
		serial = onvif.Serial
		if vendor == "Unknown" && onvif.Manufacturer != "" {
			vendor = onvif.Manufacturer
		}
		// Use ONVIF model as hostname hint if hostname is empty
		if hostname == "" && onvif.Model != "" {
			hostname = onvif.Model
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

	// JARM fingerprint
	jarmHash := ""
	for _, tlsPort := range []int{443, 8443, 8000} {
		if portSet[tlsPort] {
			jarmHash = jarmFingerprint(ip, tlsPort)
			break
		}
	}

	return &Device{
		IPAddress:       ip,
		Status:          "online",
		MACAddress:      mac,
		Hostname:        hostname,
		Manufacturer:    vendor,
		Vendor:          vendor,
		OSFamily:        osFamily,
		DeviceType:      deviceType,
		OpenPorts:       openPorts,
		Services:        services,
		ProtocolHints:   protocols,
		Vulnerabilities: []interface{}{},
		LastSeen:        time.Now().UTC().Format(time.RFC3339),
		ScanMethod:      "go-scanner",
		JARMHash:        jarmHash,
		Model:           model,
		Firmware:        firmware,
		Serial:          serial,
	}
}

// ── Main ──────────────────────────────────────────────────────────────────

func main() {
	subnet := "192.168.30"
	if len(os.Args) > 1 {
		subnet = os.Args[1]
	}

	var ips []string
	for i := 1; i <= 254; i++ {
		ips = append(ips, fmt.Sprintf("%s.%d", subnet, i))
	}

	var mu sync.Mutex
	var devices []*Device
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100)

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

	out, _ := json.Marshal(devices)
	fmt.Println(string(out))
}
