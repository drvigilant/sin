<div align="center">

# ◈ SIN // SHADOWS IN THE NETWORK

### Enterprise SOC • EDR • Autonomous Threat Hunting Platform

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Go](https://img.shields.io/badge/Go-1.21-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)

**SIN** is a high-performance Tier-1 SOC platform designed for **autonomous asset discovery, threat detection, and real-time mitigation** across enterprise and IoT/OT environments.

</div>

---

## 🧠 Overview

SIN operates as a **self-driving security layer** for your network.

It continuously maps assets, correlates vulnerabilities with real-world exploit data, and takes **automated defensive action** when critical threats are detected — all in real time.

---

## ✨ Core Features

### 🎯 Autonomous Asset Discovery
- High-speed subnet scanning using distributed sensors  
- Deep fingerprinting (MAC/OUI, vendor, firmware, serials)  
- ONVIF / ISAPI probing for IoT & surveillance devices  

### 🛡️ Dynamic Risk Engine
- CVE correlation with **CISA KEV catalog**  
- EPSS-based exploit probability scoring  
- Heuristic + deterministic risk modeling  

### ⚔️ Automated Mitigation
- Real-time **ARP-based quarantine** of compromised assets  
- Policy-driven response thresholds  
- Zero manual intervention required  

### 🧠 AI Analyst Integration
- Built-in AI console for threat interpretation  
- Generates **context-aware remediation playbooks**  
- Compatible with Ollama / Claude  

### 📊 SOC Dashboard
- Dark-mode, glass-cockpit interface  
- Real-time telemetry + forensic visibility  
- Inspired by modern EDR platforms  

---

## 🏗️ Architecture

SIN follows a **decoupled, asynchronous microservices design**:

| Component        | Technology Stack                  |
|----------------|----------------------------------|
| Frontend UI     | HTML, Grid CSS, Vanilla JS       |
| Backend API     | FastAPI (REST + WebSockets)      |
| Task Engine     | Celery + Redis                   |
| Database        | PostgreSQL / SQLite              |
| Sensors         | Python + Go (Scapy, PCAP)        |
| Deployment      | Docker + Docker Compose          |

---

## 🚀 Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/drvigilant/sin.git
cd sin

#### 2. Configure Environment
cp .env.example .env
Edit .env and add required secrets.

#### 3. Deploy Stack
``bash
docker compose up -d --build

This will start:
Nginx frontend
FastAPI backend
Celery workers
Redis + Database

### 4. Access Dashboard
```bash
http://localhost
⚙️ Configuration

### Key environment variables:

Variable	Description	Default
SIN_API_KEY	API authentication key	Required
SIN_CONFIDENCE_THRESHOLD	Risk score threshold (0–1) for auto-quarantine	0.80
SIN_REDIS_HOST	Redis host for task queue	redis
OLLAMA_URL	AI analyst endpoint	http://ollama:11434

### 💻 API Usage

SIN is API-first — everything in the UI can be triggered programmatically.

Trigger Network Scan
curl -X POST http://localhost:8000/scan/trigger \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{"subnet": "192.168.30"}'

### Check Agent Status
curl http://localhost:8000/agent/status \
  -H "X-API-Key: your_api_key"

### 🛠️ Troubleshooting

### ❌ "CANNOT REACH API"
Verify containers:
docker compose ps
Check logs:
docker compose logs api
Ensure API key consistency between frontend and .env

### ⚠️ Devices Showing "Unknown Model"
Ensure ONVIF / ISAPI is enabled on target devices
Check worker logs:
docker compose logs worker -f

### 🔄 Schema / Migration Issues
docker compose down -v
docker compose up -d --build

### 🔐 Security Notes
ARP-based mitigation can disrupt networks if misconfigured
Always test in a controlled environment before production deployment
Use strict API key management

### 🧭 Roadmap (Suggested)
 Role-Based Access Control (RBAC)
 Multi-tenant SOC support
 SIEM integrations (Splunk / Elastic)
 Advanced anomaly detection (ML models)
 Agent-based endpoint telemetry

### 🤝 Contributing

Pull requests, issues, and security discussions are welcome.

### 📜 License

MIT License (or specify your license)

<div align="center">

"Detect. Decide. Neutralize."

</div> ```
