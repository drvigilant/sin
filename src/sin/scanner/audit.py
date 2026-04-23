import os
import re
import ssl
import json
import time
import socket
import hashlib
import ipaddress
import requests
import urllib3
from enum import Enum
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from pydantic import BaseModel, Field

from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.output_parsers import PydanticOutputParser

from sin.utils.logger import get_logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = get_logger("sin.scanner.audit")


# ─────────────────────────────────────────────
#  DATA MODELS
# ─────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class Vulnerability(BaseModel):
    severity:    str = Field(description="Must be CRITICAL, HIGH, MEDIUM, or LOW")
    type:        str = Field(description="The category of the flaw")
    description: str = Field(description="Detailed explanation")
    cve:         Optional[str] = Field(default=None, description="Related CVE ID if known")
    confidence:  Optional[float] = Field(default=1.0, description="Detection confidence 0.0-1.0")


class AuditResult(BaseModel):
    findings: List[Vulnerability] = Field(description="List of discovered vulnerabilities")


@dataclass
class DeviceFingerprint:
    """Rich device profile assembled during pre-audit recon."""
    ip_address:   str
    open_ports:   List[int]
    vendor:       str        = ""
    os_family:    str        = ""
    http_banner:  str        = ""
    rtsp_banner:  str        = ""
    ftp_banner:   str        = ""
    ssh_banner:   str        = ""
    telnet_banner: str       = ""
    https_cert:   Dict       = field(default_factory=dict)
    http_headers: Dict       = field(default_factory=dict)
    http_body_snippet: str   = ""
    snmp_info:    Dict       = field(default_factory=dict)
    firmware_hints: List[str] = field(default_factory=list)
    services:     Dict[int, str] = field(default_factory=dict)   # port → service label

    def to_context_string(self) -> str:
        parts = [
            f"IP: {self.ip_address}",
            f"Ports: {self.open_ports}",
            f"Vendor: {self.vendor or 'Unknown'}",
            f"OS: {self.os_family or 'Unknown'}",
        ]
        if self.http_banner:   parts.append(f"HTTP Server: {self.http_banner}")
        if self.rtsp_banner:   parts.append(f"RTSP Server: {self.rtsp_banner}")
        if self.ftp_banner:    parts.append(f"FTP Banner: {self.ftp_banner}")
        if self.ssh_banner:    parts.append(f"SSH Banner: {self.ssh_banner}")
        if self.telnet_banner: parts.append(f"Telnet Banner: {self.telnet_banner}")
        if self.https_cert:    parts.append(f"TLS Cert: {self.https_cert}")
        if self.http_headers:  parts.append(f"HTTP Headers: {self.http_headers}")
        if self.http_body_snippet: parts.append(f"HTTP Body Snippet: {self.http_body_snippet[:300]}")
        if self.firmware_hints: parts.append(f"Firmware Hints: {self.firmware_hints}")
        if self.services:      parts.append(f"Services: {self.services}")
        return " | ".join(parts)


# ─────────────────────────────────────────────
#  SIGNATURE DATABASE  (enterprise heuristics)
# ─────────────────────────────────────────────

# Each rule is a dict with:
#   match_fields  – which fingerprint fields to search (list of attribute names)
#   patterns      – list of compiled regex patterns (ANY match triggers the rule)
#   severity      – Severity enum value
#   vuln_type     – short category label
#   description   – human-readable finding
#   cve           – optional CVE reference
#   confidence    – base confidence score (0.0–1.0)

_RAW_RULES: List[Dict[str, Any]] = [

    # ── Vendor-specific firmware / auth bypass ──────────────────────────────
    {
        "match_fields": ["http_banner", "http_body_snippet", "vendor"],
        "patterns": [r"hikvision", r"dvr[\s_-]?web", r"ipc[\s_-]?web", r"NVR Web"],
        "severity": Severity.CRITICAL,
        "vuln_type": "Auth Bypass / RCE",
        "description": (
            "Hikvision device detected. Versions prior to 5.4.5 are affected by "
            "CVE-2021-36260 (unauthenticated RCE via /SDK/webLanguage endpoint) "
            "and CVE-2017-7921 (authentication bypass). Confirm firmware version immediately."
        ),
        "cve": "CVE-2021-36260",
        "confidence": 0.85,
    },
    {
        "match_fields": ["http_banner", "http_body_snippet", "vendor"],
        "patterns": [r"dahua", r"webs server", r"dh[-_]ipc", r"dh[-_]sd"],
        "severity": Severity.CRITICAL,
        "vuln_type": "Auth Bypass / Credential Disclosure",
        "description": (
            "Dahua device detected. Affected by CVE-2021-33044 / CVE-2021-33045 "
            "(authentication bypass) and historical credential disclosure via /current_config/passwd. "
            "Verify patch status against DSA-2021-116."
        ),
        "cve": "CVE-2021-33044",
        "confidence": 0.85,
    },
    {
        "match_fields": ["http_banner", "http_body_snippet", "vendor"],
        "patterns": [r"axis[\s/]", r"vapix", r"axis communications"],
        "severity": Severity.HIGH,
        "vuln_type": "VAPIX API Exposure",
        "description": (
            "Axis device with VAPIX interface detected. Unauthenticated VAPIX endpoints "
            "can expose live streams, device config, and PTZ control (CVE-2018-10660). "
            "Restrict /axis-cgi/ to trusted networks."
        ),
        "cve": "CVE-2018-10660",
        "confidence": 0.80,
    },
    {
        "match_fields": ["http_banner", "http_body_snippet", "vendor"],
        "patterns": [r"bosch[\s/]", r"divar", r"flexidome"],
        "severity": Severity.MEDIUM,
        "vuln_type": "Bosch Firmware Exposure",
        "description": (
            "Bosch IP camera/NVR detected. Check for CVE-2019-6955 (path traversal) "
            "and ensure firmware >= 6.30 to mitigate known API injection issues."
        ),
        "cve": "CVE-2019-6955",
        "confidence": 0.75,
    },
    {
        "match_fields": ["http_banner", "http_body_snippet", "vendor"],
        "patterns": [r"hanwha", r"samsung techwin", r"wisenet"],
        "severity": Severity.HIGH,
        "vuln_type": "Hanwha/Samsung Techwin Vulnerability",
        "description": (
            "Hanwha/Samsung Techwin camera detected. Multiple CVEs (2018-1149, 2018-1150) "
            "allow unauthenticated RCE and password disclosure in older firmware. "
            "Enforce firmware update policy."
        ),
        "cve": "CVE-2018-1149",
        "confidence": 0.80,
    },
    {
        "match_fields": ["http_banner", "ftp_banner", "vendor", "http_body_snippet"],
        "patterns": [r"vivotek", r"vvtk"],
        "severity": Severity.CRITICAL,
        "vuln_type": "Stack Overflow / RCE",
        "description": (
            "Vivotek IP camera detected. CVE-2018-14933 allows unauthenticated stack-based "
            "buffer overflow in the RTSP service, leading to remote code execution without credentials."
        ),
        "cve": "CVE-2018-14933",
        "confidence": 0.82,
    },
    {
        "match_fields": ["http_banner", "http_body_snippet", "vendor"],
        "patterns": [r"tenda[\s/]", r"tenda router"],
        "severity": Severity.CRITICAL,
        "vuln_type": "Unauthenticated RCE",
        "description": (
            "Tenda router/AP detected. Multiple models have unauthenticated command injection "
            "vulnerabilities (CVE-2020-10987, CVE-2021-27702) via the goform endpoint. "
            "No authentication required to exploit."
        ),
        "cve": "CVE-2020-10987",
        "confidence": 0.83,
    },
    {
        "match_fields": ["http_banner", "http_body_snippet", "vendor"],
        "patterns": [r"d[-_]?link", r"dlink", r"dir-\d+"],
        "severity": Severity.HIGH,
        "vuln_type": "D-Link Authentication Bypass / RCE",
        "description": (
            "D-Link device detected. Numerous models are affected by hard-coded credentials, "
            "authentication bypass (CVE-2019-17621), and legacy UPnP stack overflows. "
            "Confirm EOL status – D-Link has discontinued security updates for several product lines."
        ),
        "cve": "CVE-2019-17621",
        "confidence": 0.80,
    },
    {
        "match_fields": ["http_banner", "http_body_snippet", "vendor"],
        "patterns": [r"netgear", r"wnr\d+", r"rax\d+", r"nighthawk"],
        "severity": Severity.HIGH,
        "vuln_type": "NETGEAR Pre-Auth RCE",
        "description": (
            "NETGEAR device detected. CVE-2021-34991 and PSV-2019-0076 describe pre-authentication "
            "buffer overflows in httpd. Upgrade to latest firmware; affected models include "
            "R7000, R6400, R8000, and over 70 others."
        ),
        "cve": "CVE-2021-34991",
        "confidence": 0.78,
    },
    {
        "match_fields": ["http_banner", "http_body_snippet", "vendor"],
        "patterns": [r"tp-?link", r"tplink", r"archer[\s_]c\d+"],
        "severity": Severity.HIGH,
        "vuln_type": "TP-Link Command Injection",
        "description": (
            "TP-Link device detected. CVE-2023-1389 (CVSS 9.8) is an unauthenticated command "
            "injection in the /cgi-bin/luci endpoint affecting Archer AX21 and related models. "
            "Patch immediately – actively exploited by Mirai variants."
        ),
        "cve": "CVE-2023-1389",
        "confidence": 0.82,
    },
    {
        "match_fields": ["http_banner", "http_body_snippet", "vendor"],
        "patterns": [r"mikrotik", r"routeros", r"winbox"],
        "severity": Severity.CRITICAL,
        "vuln_type": "MikroTik Chimay-Red / CVE-2018-14847",
        "description": (
            "MikroTik RouterOS detected. CVE-2018-14847 allows unauthenticated read/write "
            "of arbitrary files via Winbox port 8291, enabling full credential extraction. "
            "Also check for CVE-2019-3977/3978 (jailbreak) and ensure RouterOS >= 6.49.6."
        ),
        "cve": "CVE-2018-14847",
        "confidence": 0.90,
    },
    {
        "match_fields": ["http_banner", "vendor", "http_body_snippet"],
        "patterns": [r"ubiquiti", r"airmax", r"unifi", r"edgeos"],
        "severity": Severity.HIGH,
        "vuln_type": "Ubiquiti XSS / Auth Bypass",
        "description": (
            "Ubiquiti device detected. CVE-2021-22909 (UniFi Network Application SSRF) and "
            "Log4Shell via Log4j in affected UniFi controllers allow full RCE. "
            "Confirm UniFi controller version is >= 6.5.55."
        ),
        "cve": "CVE-2021-22909",
        "confidence": 0.78,
    },

    # ── Embedded Web Server fingerprints ────────────────────────────────────
    {
        "match_fields": ["http_banner"],
        "patterns": [r"goahead", r"go ahead"],
        "severity": Severity.HIGH,
        "vuln_type": "GoAhead Embedded Server – RCE",
        "description": (
            "GoAhead embedded web server detected. CVE-2017-17562 allows unauthenticated "
            "remote code execution by injecting environment variables into CGI scripts. "
            "Widely exploited in IP cameras and NVRs running GoAhead < 3.6.5."
        ),
        "cve": "CVE-2017-17562",
        "confidence": 0.88,
    },
    {
        "match_fields": ["http_banner"],
        "patterns": [r"uc-httpd", r"uc httpd"],
        "severity": Severity.CRITICAL,
        "vuln_type": "UC-HTTPd Directory Traversal",
        "description": (
            "UC-HTTPd server detected (common in cheap IP cameras). CVE-2018-10088 allows "
            "unauthenticated directory traversal to read /etc/passwd and other sensitive files. "
            "No patch exists – isolate this device immediately."
        ),
        "cve": "CVE-2018-10088",
        "confidence": 0.92,
    },
    {
        "match_fields": ["http_banner"],
        "patterns": [r"mini_httpd", r"mini-httpd"],
        "severity": Severity.HIGH,
        "vuln_type": "mini_httpd Path Traversal",
        "description": (
            "mini_httpd server detected. Versions <= 1.30 are vulnerable to path traversal "
            "(CVE-2018-18778) allowing attackers to read files outside the web root."
        ),
        "cve": "CVE-2018-18778",
        "confidence": 0.85,
    },
    {
        "match_fields": ["http_banner"],
        "patterns": [r"lighttpd/1\.[0-3]\.", r"lighttpd/1\.4\.[0-4][0-9](?!\d)"],
        "severity": Severity.MEDIUM,
        "vuln_type": "Outdated lighttpd",
        "description": (
            "Outdated lighttpd version detected. Versions before 1.4.56 have multiple "
            "vulnerabilities including HTTP smuggling (CVE-2022-22707). Upgrade to >= 1.4.67."
        ),
        "cve": "CVE-2022-22707",
        "confidence": 0.70,
    },
    {
        "match_fields": ["http_banner"],
        "patterns": [r"thttpd"],
        "severity": Severity.MEDIUM,
        "vuln_type": "thttpd Unmaintained Server",
        "description": (
            "thttpd detected – this server has been unmaintained since 2018 and has known "
            "denial-of-service and information disclosure issues. Consider replacing with an "
            "actively maintained alternative."
        ),
        "confidence": 0.70,
    },

    # ── Dangerous open ports / services ─────────────────────────────────────
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b23\b"],
        "severity": Severity.CRITICAL,
        "vuln_type": "Telnet Exposed",
        "description": (
            "Telnet (port 23) is open. Telnet transmits all data in cleartext including "
            "credentials. This is a primary Mirai botnet infection vector. Disable immediately "
            "and replace with SSH if remote management is required."
        ),
        "confidence": 0.98,
    },
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b21\b"],
        "severity": Severity.HIGH,
        "vuln_type": "Anonymous / Cleartext FTP",
        "description": (
            "FTP (port 21) is open. FTP transmits credentials in plaintext. Many embedded "
            "devices allow anonymous login by default. Verify authentication is enforced and "
            "consider replacing with SFTP."
        ),
        "confidence": 0.90,
    },
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b161\b"],
        "severity": Severity.HIGH,
        "vuln_type": "SNMP Exposed",
        "description": (
            "SNMP (UDP 161) is open. Community string 'public' is default on most IoT devices "
            "and allows full MIB enumeration, network topology disclosure, and on some devices "
            "configuration write access. Disable if unused or restrict with SNMPv3 and ACLs."
        ),
        "confidence": 0.88,
    },
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b5985\b", r"\b5986\b"],
        "severity": Severity.HIGH,
        "vuln_type": "WinRM Exposed",
        "description": (
            "Windows Remote Management (WinRM) ports 5985/5986 are open. This service should "
            "never be exposed on IoT/OT networks. Restrict to trusted management subnets only."
        ),
        "confidence": 0.90,
    },
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b7547\b"],
        "severity": Severity.CRITICAL,
        "vuln_type": "TR-069 CWMP Exposed",
        "description": (
            "TR-069 CWMP port 7547 is open. CVE-2016-10372 (Misfortune Cookie / CERT-Bund) "
            "allows unauthenticated RCE on millions of CPE devices. This port should only be "
            "reachable by the ISP's ACS server – never from the internet."
        ),
        "cve": "CVE-2016-10372",
        "confidence": 0.95,
    },
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b8291\b"],
        "severity": Severity.CRITICAL,
        "vuln_type": "MikroTik Winbox Port Exposed",
        "description": (
            "MikroTik Winbox management port (8291) is publicly accessible. "
            "CVE-2018-14847 allows unauthenticated credential extraction from this port. "
            "Block immediately on the WAN interface."
        ),
        "cve": "CVE-2018-14847",
        "confidence": 0.95,
    },
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b47808\b"],
        "severity": Severity.HIGH,
        "vuln_type": "BACnet/IP Exposed (OT Protocol)",
        "description": (
            "BACnet/IP (UDP 47808) detected – this is a building automation / SCADA protocol "
            "that should never be internet-accessible. Exposure allows device enumeration, "
            "command injection, and disruption of HVAC, lighting, and access control systems."
        ),
        "confidence": 0.92,
    },
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b102\b"],
        "severity": Severity.CRITICAL,
        "vuln_type": "S7comm (Siemens PLC) Exposed",
        "description": (
            "S7comm port 102 detected. This Siemens PLC communication protocol has no "
            "authentication. Exposure allows reading/writing PLC memory and I/O, potentially "
            "enabling physical process manipulation (cf. Stuxnet attack vector)."
        ),
        "confidence": 0.95,
    },
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b502\b"],
        "severity": Severity.CRITICAL,
        "vuln_type": "Modbus TCP Exposed (OT Protocol)",
        "description": (
            "Modbus TCP (port 502) is open. Modbus has no authentication or encryption. "
            "Exposure allows unauthenticated read/write of industrial process registers. "
            "Restrict to isolated OT VLAN with strict ACLs."
        ),
        "confidence": 0.95,
    },
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b4840\b"],
        "severity": Severity.HIGH,
        "vuln_type": "OPC-UA Exposed",
        "description": (
            "OPC-UA (port 4840) is open. While OPC-UA has built-in security modes, many "
            "deployments use 'None' security policy allowing unauthenticated read of process "
            "data. Verify security mode is not set to None in the endpoint configuration."
        ),
        "confidence": 0.85,
    },

    # ── TLS / Certificate issues ─────────────────────────────────────────────
    {
        "match_fields": ["https_cert"],
        "patterns": [r"self.signed|self_signed|issuer.*CN.*subject.*CN.*same"],
        "severity": Severity.MEDIUM,
        "vuln_type": "Self-Signed TLS Certificate",
        "description": (
            "Self-signed TLS certificate detected. This certificate cannot be validated "
            "by a trusted CA, making the device susceptible to MITM attacks. "
            "Deploy a certificate from a trusted CA or an internal PKI."
        ),
        "confidence": 0.90,
    },
    {
        "match_fields": ["https_cert"],
        "patterns": [r"expired|not_after.*20(1[0-9]|2[0-2])"],
        "severity": Severity.HIGH,
        "vuln_type": "Expired TLS Certificate",
        "description": (
            "TLS certificate is expired. Expired certificates indicate poor security hygiene "
            "and may cause TLS validation to be bypassed by clients, enabling MITM attacks."
        ),
        "confidence": 0.92,
    },

    # ── HTTP security header gaps ─────────────────────────────────────────────
    {
        "match_fields": ["http_headers"],
        "patterns": [r"x-powered-by", r"x_powered_by"],
        "severity": Severity.LOW,
        "vuln_type": "Technology Disclosure (X-Powered-By)",
        "description": (
            "X-Powered-By header present, disclosing server technology/version to attackers. "
            "Remove this header from the HTTP server configuration to reduce fingerprinting surface."
        ),
        "confidence": 0.95,
    },
    {
        "match_fields": ["http_headers"],
        "patterns": [r"\"server\":\s*\"apache/1\.", r"\"server\":\s*\"apache/2\.[0-3]\."],
        "severity": Severity.MEDIUM,
        "vuln_type": "Outdated Apache HTTP Server",
        "description": (
            "Outdated Apache HTTP Server detected. Multiple high-severity CVEs affect Apache "
            "versions prior to 2.4.55. Upgrade immediately and review the Apache security "
            "changelog for applicable patches."
        ),
        "confidence": 0.80,
    },
    {
        "match_fields": ["http_headers"],
        "patterns": [r"\"server\":\s*\"nginx/1\.[0-9]\.", r"\"server\":\s*\"nginx/1\.1[0-7]\."],
        "severity": Severity.MEDIUM,
        "vuln_type": "Outdated NGINX",
        "description": (
            "Outdated NGINX version detected. Versions prior to 1.25.x may be affected by "
            "HTTP/2 Rapid Reset (CVE-2023-44487) and other vulnerabilities. Upgrade to latest stable."
        ),
        "cve": "CVE-2023-44487",
        "confidence": 0.75,
    },

    # ── Banner / credential hints ────────────────────────────────────────────
    {
        "match_fields": ["telnet_banner", "ftp_banner"],
        "patterns": [r"busybox", r"linux.*mips", r"linux.*arm"],
        "severity": Severity.HIGH,
        "vuln_type": "Linux/BusyBox IoT Device (Mirai Target)",
        "description": (
            "BusyBox/Linux-based IoT device detected on a cleartext management port. "
            "These devices are primary Mirai botnet targets. Verify all default credentials "
            "have been changed and that Telnet/FTP are disabled."
        ),
        "confidence": 0.85,
    },
    {
        "match_fields": ["ftp_banner", "telnet_banner"],
        "patterns": [r"220.*ftp", r"login:", r"username:", r"password:"],
        "severity": Severity.HIGH,
        "vuln_type": "Cleartext Credential Prompt Exposed",
        "description": (
            "Authentication prompt exposed on a cleartext protocol (FTP/Telnet). "
            "Credentials are transmitted unencrypted. Test for default credentials "
            "(admin/admin, root/root, admin/password, etc.) and enforce encrypted alternatives."
        ),
        "confidence": 0.90,
    },
    {
        "match_fields": ["ssh_banner"],
        "patterns": [r"openssh_[1-6]\.", r"dropbear_20(0[0-9]|1[0-6])"],
        "severity": Severity.MEDIUM,
        "vuln_type": "Outdated SSH Daemon",
        "description": (
            "Outdated SSH daemon detected. Old OpenSSH versions (< 8.x) and Dropbear < 2020 "
            "have known vulnerabilities including user enumeration (CVE-2018-15473) and "
            "memory corruption issues. Upgrade to current versions."
        ),
        "cve": "CVE-2018-15473",
        "confidence": 0.75,
    },

    # ── Firmware / body content hints ────────────────────────────────────────
    {
        "match_fields": ["http_body_snippet"],
        "patterns": [r"default password", r"factory password", r"admin.*admin"],
        "severity": Severity.CRITICAL,
        "vuln_type": "Default Credentials Advertised",
        "description": (
            "The device web interface references default credentials. This strongly indicates "
            "factory-default authentication has not been changed. Default credentials are "
            "exploited within minutes of internet exposure (cf. Mirai, Mozi botnets)."
        ),
        "confidence": 0.95,
    },
    {
        "match_fields": ["http_body_snippet"],
        "patterns": [r"/cgi-bin/", r"cgi\.exe"],
        "severity": Severity.MEDIUM,
        "vuln_type": "CGI Interface Detected",
        "description": (
            "CGI interface detected. CGI is historically vulnerable to Shellshock "
            "(CVE-2014-6271) and various injection attacks. Verify the CGI runtime is "
            "fully patched and validate all input rigorously."
        ),
        "cve": "CVE-2014-6271",
        "confidence": 0.65,
    },
    {
        "match_fields": ["http_body_snippet", "firmware_hints"],
        "patterns": [r"firmware[\s_-]?v?[0-1]\.\d", r"version.*0\.\d"],
        "severity": Severity.HIGH,
        "vuln_type": "Pre-Release / Alpha Firmware",
        "description": (
            "Firmware version string suggests a pre-release or early version (0.x or 1.x). "
            "Alpha/beta firmware frequently lacks hardening, contains debug interfaces, "
            "and has not been through security review. Update to a stable production release."
        ),
        "confidence": 0.70,
    },
    {
        "match_fields": ["http_body_snippet", "http_headers"],
        "patterns": [r"debug", r"diagnostic", r"maintenance mode"],
        "severity": Severity.HIGH,
        "vuln_type": "Debug / Maintenance Mode Active",
        "description": (
            "Debug or maintenance mode indicator found. Devices in debug mode often expose "
            "internal APIs, verbose error messages, and unauthenticated diagnostic endpoints "
            "that can be abused for information disclosure or RCE."
        ),
        "confidence": 0.80,
    },

    # ── Protocol-level misconfigurations ────────────────────────────────────
    {
        "match_fields": ["rtsp_banner", "open_ports"],
        "patterns": [r"\b554\b", r"rtsp"],
        "severity": Severity.MEDIUM,
        "vuln_type": "Unauthenticated RTSP Stream",
        "description": (
            "RTSP (port 554) is open. Many IP cameras serve live video streams without "
            "authentication by default. Verify that RTSP requires credentials via "
            "rtsp://<ip>/stream and restrict access at the firewall level."
        ),
        "confidence": 0.80,
    },
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b9100\b"],
        "severity": Severity.HIGH,
        "vuln_type": "RAW Print Port Exposed (JetDirect)",
        "description": (
            "TCP port 9100 (JetDirect / RAW printing) is open. This port allows unauthenticated "
            "PJL commands that can extract device info, configuration files, stored print jobs, "
            "and crash or reconfigure the printer."
        ),
        "confidence": 0.90,
    },
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b631\b"],
        "severity": Severity.MEDIUM,
        "vuln_type": "CUPS / IPP Print Service Exposed",
        "description": (
            "CUPS/IPP (port 631) is open. CVE-2023-32360 and related CUPS vulnerabilities "
            "allow unauthenticated information disclosure and potential RCE. "
            "Restrict this port to internal networks only."
        ),
        "cve": "CVE-2023-32360",
        "confidence": 0.82,
    },
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b1883\b", r"\b8883\b"],
        "severity": Severity.HIGH,
        "vuln_type": "MQTT Broker Exposed",
        "description": (
            "MQTT broker port detected (1883 cleartext / 8883 TLS). Many IoT deployments "
            "run MQTT without authentication, allowing any client to subscribe to all topics "
            "and publish arbitrary messages to connected devices. Enforce broker authentication."
        ),
        "confidence": 0.88,
    },
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b5672\b", r"\b15672\b"],
        "severity": Severity.HIGH,
        "vuln_type": "AMQP / RabbitMQ Exposed",
        "description": (
            "AMQP (5672) or RabbitMQ management UI (15672) detected. Default credentials "
            "(guest/guest) are still active on many deployments. Restrict to trusted hosts "
            "and rotate all credentials immediately."
        ),
        "confidence": 0.85,
    },
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b6379\b"],
        "severity": Severity.CRITICAL,
        "vuln_type": "Redis Exposed Without Auth",
        "description": (
            "Redis (port 6379) is accessible. Redis has no authentication by default. "
            "Unauthenticated access allows full data dump, config rewrite, and SSH key "
            "injection for OS-level access. Bind to loopback and require AUTH immediately."
        ),
        "confidence": 0.95,
    },
    {
        "match_fields": ["open_ports"],
        "patterns": [r"\b27017\b", r"\b27018\b"],
        "severity": Severity.CRITICAL,
        "vuln_type": "MongoDB Exposed Without Auth",
        "description": (
            "MongoDB (27017/27018) is accessible. Older MongoDB versions and misconfigured "
            "instances have no authentication enabled by default, allowing full database "
            "read/write access without credentials."
        ),
        "confidence": 0.93,
    },
]


# ─────────────────────────────────────────────
#  COMPILED RULE ENGINE
# ─────────────────────────────────────────────

@dataclass
class CompiledRule:
    match_fields: List[str]
    patterns:     List[re.Pattern]
    severity:     Severity
    vuln_type:    str
    description:  str
    cve:          Optional[str] = None
    confidence:   float = 1.0


def _compile_rules(raw: List[Dict]) -> List[CompiledRule]:
    compiled = []
    for r in raw:
        try:
            compiled.append(CompiledRule(
                match_fields=r["match_fields"],
                patterns=[re.compile(p, re.IGNORECASE) for p in r["patterns"]],
                severity=r["severity"],
                vuln_type=r["vuln_type"],
                description=r["description"],
                cve=r.get("cve"),
                confidence=r.get("confidence", 1.0),
            ))
        except re.error as e:
            logger.warning(f"Rule compilation error for '{r.get('vuln_type')}': {e}")
    return compiled


COMPILED_RULES: List[CompiledRule] = _compile_rules(_RAW_RULES)


# ─────────────────────────────────────────────
#  RECON / BANNER GRABBING
# ─────────────────────────────────────────────

class ReconEngine:
    """
    Lightweight, parallelism-friendly recon module.
    Grabs banners and metadata across all relevant protocols.
    """

    TIMEOUT = 3

    # Ports to probe and their service labels
    PORT_SERVICE_MAP: Dict[int, str] = {
        21:    "FTP",
        22:    "SSH",
        23:    "Telnet",
        80:    "HTTP",
        443:   "HTTPS",
        554:   "RTSP",
        631:   "IPP/CUPS",
        1883:  "MQTT",
        1900:  "UPnP/SSDP",
        4840:  "OPC-UA",
        5672:  "AMQP",
        6379:  "Redis",
        7547:  "TR-069",
        8080:  "HTTP-Alt",
        8081:  "HTTP-Alt2",
        8291:  "Winbox",
        8883:  "MQTT-TLS",
        9100:  "JetDirect",
        15672: "RabbitMQ-UI",
        27017: "MongoDB",
        47808: "BACnet",
        161:   "SNMP",
        502:   "Modbus",
    }

    def gather(self, ip: str, open_ports: List[int]) -> DeviceFingerprint:
        fp = DeviceFingerprint(ip_address=ip, open_ports=open_ports)

        for port in open_ports:
            label = self.PORT_SERVICE_MAP.get(port, f"TCP/{port}")
            fp.services[port] = label

        # HTTP / HTTPS
        for port in [80, 8080, 8081, 8888, 8000]:
            if port in open_ports:
                banner, headers, body = self._grab_http(ip, port, tls=False)
                logger.debug(f"  [recon] HTTP {ip}:{port} → banner={repr(banner[:60])} body={len(body)}b")
                if banner or headers or body:
                    fp.http_banner       = fp.http_banner or banner
                    fp.http_headers      = fp.http_headers or headers
                    fp.http_body_snippet = fp.http_body_snippet or body
                    break

        for port in [443, 8443]:
            if port in open_ports:
                banner, headers, body = self._grab_http(ip, port, tls=True)
                cert_info             = self._grab_tls_cert(ip, port)
                logger.debug(f"  [recon] HTTPS {ip}:{port} → banner={repr(banner[:60])} cert={bool(cert_info)}")
                if banner or headers or body:
                    fp.http_banner       = fp.http_banner or banner
                    fp.http_headers      = fp.http_headers or headers
                    fp.http_body_snippet = fp.http_body_snippet or body
                if cert_info:
                    fp.https_cert = cert_info
                break

        # Cleartext TCP services
        if 554 in open_ports:
            fp.rtsp_banner = self._grab_rtsp(ip, 554)
            logger.debug(f"  [recon] RTSP {ip}:554 → {repr(fp.rtsp_banner[:60])}")

        if 21 in open_ports:
            fp.ftp_banner = self._grab_tcp_banner(ip, 21)
            logger.debug(f"  [recon] FTP {ip}:21 → {repr(fp.ftp_banner[:60])}")

        if 22 in open_ports:
            fp.ssh_banner = self._grab_tcp_banner(ip, 22)
            logger.debug(f"  [recon] SSH {ip}:22 → {repr(fp.ssh_banner[:60])}")

        if 23 in open_ports:
            fp.telnet_banner = self._grab_tcp_banner(ip, 23)
            logger.debug(f"  [recon] Telnet {ip}:23 → {repr(fp.telnet_banner[:60])}")

        # Firmware / version hints from body
        if fp.http_body_snippet:
            fp.firmware_hints = self._extract_firmware_hints(fp.http_body_snippet)

        logger.debug(
            f"  [recon] Fingerprint summary for {ip}: "
            f"ports={open_ports} http_banner={repr(fp.http_banner)} "
            f"ssh={repr(fp.ssh_banner[:40])} ftp={repr(fp.ftp_banner[:40])} "
            f"body_len={len(fp.http_body_snippet)} cert={bool(fp.https_cert)}"
        )
        return fp

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _grab_http(self, ip: str, port: int, tls: bool) -> Tuple[str, Dict, str]:
        scheme = "https" if tls else "http"
        try:
            r = requests.get(
                f"{scheme}://{ip}:{port}",
                timeout=self.TIMEOUT,
                verify=False,
                allow_redirects=True,
            )
            server  = r.headers.get("Server", "")
            headers = {k.lower(): v for k, v in r.headers.items()}
            body    = r.text[:2000] if r.text else ""
            return server, headers, body
        except requests.exceptions.RequestException:
            return "", {}, ""

    def _grab_tls_cert(self, ip: str, port: int) -> Dict:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=self.TIMEOUT) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as tls_sock:
                    cert = tls_sock.getpeercert()
                    if not cert:
                        return {"self_signed": True}
                    not_after  = cert.get("notAfter", "")
                    issuer     = dict(x[0] for x in cert.get("issuer", []))
                    subject    = dict(x[0] for x in cert.get("subject", []))
                    expired    = self._cert_is_expired(not_after)
                    self_signed = (issuer.get("commonName") == subject.get("commonName"))
                    return {
                        "issuer":     issuer,
                        "subject":    subject,
                        "not_after":  not_after,
                        "expired":    expired,
                        "self_signed": self_signed,
                    }
        except Exception:
            return {}

    def _cert_is_expired(self, not_after: str) -> bool:
        if not not_after:
            return False
        try:
            from datetime import datetime
            dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            return dt < datetime.utcnow()
        except Exception:
            return False

    def _grab_rtsp(self, ip: str, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.TIMEOUT)
                s.connect((ip, port))
                s.sendall(
                    f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode()
                )
                raw = s.recv(1024).decode(errors="ignore")
                for line in raw.split("\r\n"):
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()
                return raw[:200]
        except Exception:
            return ""

    def _grab_tcp_banner(self, ip: str, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.TIMEOUT)
                s.connect((ip, port))
                # Some services send a banner on connect; others need a probe.
                try:
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except Exception:
                    banner = ""
                return banner[:300]
        except Exception:
            return ""

    def _extract_firmware_hints(self, body: str) -> List[str]:
        hints = []
        for pattern in [
            r"firmware[\s:_-]+v?([\d.]+)",
            r"version[\s:]+v?([\d.]+)",
            r"release[\s:]+v?([\d.]+)",
            r"build[\s:]+(\d{8,})",
        ]:
            matches = re.findall(pattern, body, re.IGNORECASE)
            hints.extend(matches)
        return list(set(hints))[:5]


# ─────────────────────────────────────────────
#  HEURISTIC ENGINE  (upgraded)
# ─────────────────────────────────────────────

class HeuristicEngine:
    """
    Rule-based vulnerability scanner.
    Operates without any AI API calls – fully offline capable.
    Uses the compiled signature database above.
    """

    # Direct port-to-finding map — fires regardless of banner content.
    # This is the safety net: if recon gets no banners, we still flag known-dangerous ports.
    _PORT_FINDINGS: Dict[int, Dict] = {
        23:    {"severity": "CRITICAL", "type": "Telnet Exposed",
                "description": "Telnet (port 23) is open. Cleartext protocol, primary Mirai vector. Disable immediately.",
                "cve": None, "confidence": 0.99},
        21:    {"severity": "HIGH",     "type": "FTP Exposed",
                "description": "FTP (port 21) open. Cleartext credentials. Verify auth; replace with SFTP.",
                "cve": None, "confidence": 0.95},
        161:   {"severity": "HIGH",     "type": "SNMP Exposed",
                "description": "SNMP UDP/161 open. Default community string 'public' allows full MIB read/write.",
                "cve": None, "confidence": 0.92},
        502:   {"severity": "CRITICAL", "type": "Modbus TCP Exposed",
                "description": "Modbus TCP (502) open. No auth, no encryption. Unauthenticated OT register R/W.",
                "cve": None, "confidence": 0.99},
        102:   {"severity": "CRITICAL", "type": "S7comm (Siemens PLC) Exposed",
                "description": "S7comm port 102 open. No authentication — full PLC memory R/W access.",
                "cve": None, "confidence": 0.99},
        47808: {"severity": "HIGH",     "type": "BACnet/IP Exposed",
                "description": "BACnet/IP UDP/47808 open. Building automation protocol — never internet-accessible.",
                "cve": None, "confidence": 0.97},
        7547:  {"severity": "CRITICAL", "type": "TR-069 CWMP Exposed",
                "description": "TR-069 CWMP port 7547 open. CVE-2016-10372 unauthenticated RCE.",
                "cve": "CVE-2016-10372", "confidence": 0.97},
        8291:  {"severity": "CRITICAL", "type": "MikroTik Winbox Port Exposed",
                "description": "Winbox port 8291 accessible. CVE-2018-14847 unauthenticated credential extraction.",
                "cve": "CVE-2018-14847", "confidence": 0.97},
        6379:  {"severity": "CRITICAL", "type": "Redis Exposed",
                "description": "Redis port 6379 open. No auth by default — full data access + OS compromise via config write.",
                "cve": None, "confidence": 0.98},
        27017: {"severity": "CRITICAL", "type": "MongoDB Exposed",
                "description": "MongoDB 27017 open. No auth on many deployments — full database read/write.",
                "cve": None, "confidence": 0.97},
        1883:  {"severity": "HIGH",     "type": "MQTT Broker Exposed",
                "description": "MQTT port 1883 open. Many brokers have no auth — subscribe/publish to all IoT topics.",
                "cve": None, "confidence": 0.93},
        9100:  {"severity": "HIGH",     "type": "RAW Print Port Exposed",
                "description": "JetDirect port 9100 open. Unauthenticated PJL commands allow config read/crash.",
                "cve": None, "confidence": 0.93},
        4840:  {"severity": "HIGH",     "type": "OPC-UA Exposed",
                "description": "OPC-UA port 4840 open. Verify security mode is not 'None'.",
                "cve": None, "confidence": 0.88},
        5985:  {"severity": "HIGH",     "type": "WinRM Exposed",
                "description": "WinRM port 5985 open on IoT/OT network. Should never be publicly reachable.",
                "cve": None, "confidence": 0.93},
        554:   {"severity": "MEDIUM",   "type": "RTSP Stream Exposed",
                "description": "RTSP port 554 open. Many cameras stream without authentication by default.",
                "cve": None, "confidence": 0.85},
    }

    def scan(self, fp: DeviceFingerprint) -> List[Dict]:
        findings: List[Dict] = []
        seen_types: set = set()

        # ── Layer 1: Port-presence (no banner needed) ─────────────────────────
        for port in fp.open_ports:
            pf = self._PORT_FINDINGS.get(port)
            if pf and pf["type"] not in seen_types:
                seen_types.add(pf["type"])
                findings.append({**pf, "engine": "heuristic"})
                logger.debug(f"  [heuristic] Port {port} → {pf['type']}")

        # ── Layer 2: Signature/banner matching ───────────────────────────────
        # Build a lookup of field-name → searchable string
        field_values: Dict[str, str] = {
            "open_ports":        str(fp.open_ports),
            "vendor":            fp.vendor.lower(),
            "http_banner":       fp.http_banner.lower(),
            "rtsp_banner":       fp.rtsp_banner.lower(),
            "ftp_banner":        fp.ftp_banner.lower(),
            "ssh_banner":        fp.ssh_banner.lower(),
            "telnet_banner":     fp.telnet_banner.lower(),
            "https_cert":        json.dumps(fp.https_cert).lower(),
            "http_headers":      json.dumps(fp.http_headers).lower(),
            "http_body_snippet": fp.http_body_snippet.lower(),
            "firmware_hints":    " ".join(fp.firmware_hints).lower(),
        }

        for rule in COMPILED_RULES:
            corpus = " ".join(field_values.get(f, "") for f in rule.match_fields)
            if not corpus.strip():
                continue

            matched = any(p.search(corpus) for p in rule.patterns)
            if not matched:
                continue

            if rule.vuln_type in seen_types:
                continue
            seen_types.add(rule.vuln_type)
            logger.debug(f"  [heuristic] Signature matched → {rule.vuln_type}")

            findings.append({
                "severity":    rule.severity.value,
                "type":        rule.vuln_type,
                "description": rule.description,
                "cve":         rule.cve,
                "confidence":  rule.confidence,
                "engine":      "heuristic",
            })

        # Sort by severity priority
        _order = {Severity.CRITICAL.value: 0, Severity.HIGH.value: 1,
                  Severity.MEDIUM.value: 2, Severity.LOW.value: 3, Severity.INFO.value: 4}
        findings.sort(key=lambda x: _order.get(x["severity"], 99))

        if findings:
            logger.warning(
                f"🔍 Heuristic Engine: {len(findings)} finding(s) on {fp.ip_address} "
                f"[CRIT:{sum(1 for f in findings if f['severity']=='CRITICAL')} "
                f"HIGH:{sum(1 for f in findings if f['severity']=='HIGH')}]"
            )
        else:
            logger.info(f"✅ Heuristic Engine: {fp.ip_address} matched no signatures.")

        return findings


# ─────────────────────────────────────────────
#  MAIN AUDITOR  (orchestrator)
# ─────────────────────────────────────────────

class VulnerabilityAuditor:
    """
    Dual-engine IoT/OT vulnerability auditor.

    Pro mode  – DeepSeek AI analysis (requires DEEPSEEK_API_KEY)
    Basic mode – Offline heuristic rule engine (no API needed)

    Both engines now share a rich DeviceFingerprint built by ReconEngine,
    so even the heuristic path has far deeper context than before.
    """

    def __init__(self):
        self.api_key = os.environ.get("DEEPSEEK_API_KEY", "")
        self.recon   = ReconEngine()
        self.heuristic = HeuristicEngine()

        self.llm = None
        if self.api_key and self.api_key not in ("", "your-deepseek-api-key-goes-here"):
            try:
                self.llm = ChatOpenAI(
                    api_key=self.api_key,
                    base_url="https://api.deepseek.com",
                    model="deepseek-chat",
                    temperature=0.1,
                )
                logger.info("✅ DeepSeek Pro engine initialised.")
            except Exception as e:
                logger.error(f"Failed to initialise DeepSeek LLM: {e}")

        self.parser = PydanticOutputParser(pydantic_object=AuditResult)

        self.prompt = PromptTemplate(
            template="""
You are an elite IoT/OT Security Analyst conducting a professional penetration test.
Analyse the following recon data and identify exploitable vulnerabilities, severe
misconfigurations, and attack chains. Prioritise findings by real-world exploitability.
Do NOT produce findings for theoretical issues that have no known exploitation path.

--- RECONNAISSANCE DATA ---
{context}
----------------------------
{format_instructions}
""",
            input_variables=["context"],
            partial_variables={"format_instructions": self.parser.get_format_instructions()},
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def audit_device(
        self,
        ip_address: str,
        open_ports: List[int],
        vendor: str = "",
        os_family: str = "",
    ) -> List[Dict]:
        """
        Full audit pipeline:
          1. Recon – build a rich DeviceFingerprint
          2. Pro path  – AI analysis via DeepSeek (if available)
          3. Basic path – heuristic rule engine (always runs as fallback or standalone)
          4. Merge & deduplicate results from both engines when both succeed
        """
        # Validate IP
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            logger.error(f"Invalid IP address: {ip_address}")
            return []

        # Step 1: Recon
        logger.info(f"🔎 Recon phase starting for {ip_address} ...")
        fp = self.recon.gather(ip_address, open_ports)
        if vendor:
            fp.vendor = vendor
        if os_family:
            fp.os_family = os_family

        # Step 2: Always run heuristics (fast, offline, zero cost)
        heuristic_findings = self.heuristic.scan(fp)

        # Step 3: Try AI if available
        if self.llm is None:
            logger.info(f"⚡ Pro AI disabled. Heuristic-only scan for {ip_address}.")
            return heuristic_findings

        logger.info(f"🧠 DeepSeek Pro audit initiating for {ip_address} ...")
        try:
            context = fp.to_context_string()
            _input  = self.prompt.format_prompt(context=context)
            output  = self.llm.invoke(_input.to_string())
            parsed  = self.parser.parse(output.content)
            ai_findings = [
                {**v.model_dump(), "engine": "ai"}
                for v in parsed.findings
            ]

            # Merge: AI findings take precedence; heuristic fills gaps
            merged = self._merge_findings(ai_findings, heuristic_findings)
            logger.warning(
                f"🎯 Combined audit: {len(merged)} total finding(s) on {ip_address}"
            )
            return merged

        except Exception as e:
            logger.warning(
                f"⚠️ Pro API unavailable ({e}). Falling back to heuristic engine for {ip_address}."
            )
            return heuristic_findings

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _merge_findings(
        self,
        ai_findings: List[Dict],
        heuristic_findings: List[Dict],
    ) -> List[Dict]:
        """
        Merge AI and heuristic results, deduplicating by normalised vuln type.
        AI findings take precedence for overlap; unique heuristic findings are appended.
        """
        seen: set = set()
        merged: List[Dict] = []

        for f in ai_findings:
            key = self._normalise_key(f.get("type", ""))
            seen.add(key)
            merged.append(f)

        for f in heuristic_findings:
            key = self._normalise_key(f.get("type", ""))
            if key not in seen:
                seen.add(key)
                merged.append(f)

        _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        merged.sort(key=lambda x: _order.get(x.get("severity", "INFO"), 99))
        return merged

    @staticmethod
    def _normalise_key(s: str) -> str:
        return re.sub(r"[^a-z0-9]", "", s.lower())
