import streamlit as st
import streamlit.components.v1 as components
import os

API_URL = "http://localhost:8000"
API_KEY = os.getenv("SIN_API_KEY", "a634fd2d20eb8dd013eab32bdbf9529694abb5e46a35dd92d531faf34f1f0291")

st.set_page_config(page_title="SIN // SOC PLATFORM", layout="wide")

st.markdown("""
    <style>
        #MainMenu, footer, header {visibility: hidden;}
        .block-container {padding: 0px !important; max-width: 100% !important;}
        iframe {border: none;}
    </style>
""", unsafe_allow_html=True)

SOC_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #0b0f19; --surface: #141b2d; --surface-2: #1e293b;
  --border: #334155; --text: #f8fafc; --text-dim: #94a3b8;
  --red: #ef4444; --orange: #f59e0b; --green: #10b981; --blue: #3b82f6;
  --font-mono: 'JetBrains Mono', monospace; --font-sans: 'Inter', sans-serif;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: var(--font-sans); background: var(--bg); color: var(--text); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }

/* Top Navbar */
.navbar { height: 56px; border-bottom: 1px solid var(--border); background: var(--surface); display: flex; align-items: center; justify-content: space-between; padding: 0 24px; }
.logo { font-family: var(--font-mono); font-weight: 700; font-size: 16px; letter-spacing: 2px; color: var(--blue); }

/* Metrics */
.metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px; background: var(--border); border-bottom: 1px solid var(--border); }
.metric-box { background: var(--surface); padding: 16px 24px; }
.m-title { font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 600; letter-spacing: 1px; margin-bottom: 8px; }
.m-value { font-size: 28px; font-family: var(--font-mono); }

/* Main Grid */
.container { display: flex; flex: 1; overflow: hidden; }
.table-area { flex: 1; overflow-y: auto; padding: 24px; }

/* Table */
table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; }
th { text-align: left; padding: 12px 16px; font-size: 11px; text-transform: uppercase; color: var(--text-dim); border-bottom: 1px solid var(--border); font-weight: 600; }
tr { border-bottom: 1px solid var(--border); }
tbody tr:hover { background: var(--surface-2); }
td { padding: 16px; font-size: 13px; vertical-align: top; }
.ip-col { font-family: var(--font-mono); font-weight: 700; color: var(--blue); }
.mac-col { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); }
.fw-badge { display: inline-block; padding: 2px 6px; background: rgba(255,255,255,0.1); border-radius: 4px; font-size: 10px; font-family: var(--font-mono); margin-top: 4px; }
.telemetry-box { font-size: 11px; color: var(--orange); font-family: var(--font-mono); margin-top: 6px; }

/* Vulnerability Rows */
.vuln-row { background: rgba(239, 68, 68, 0.05) !important; border-top: none; }
.vuln-card { margin-top: 8px; padding: 8px 12px; border-left: 2px solid var(--red); background: rgba(0,0,0,0.2); font-size: 12px; }
.kev-badge { display: inline-block; background: var(--red); color: white; font-weight: 700; padding: 2px 6px; border-radius: 4px; font-size: 10px; margin-left: 8px;}

/* Buttons */
.btn { padding: 6px 12px; border-radius: 4px; font-size: 11px; font-weight: 600; cursor: pointer; border: 1px solid transparent; text-transform: uppercase; }
.btn-iso { background: transparent; border-color: var(--red); color: var(--red); }
.btn-iso:hover { background: var(--red); color: white; }
.btn-scan { background: var(--blue); color: white; padding: 8px 16px; }
</style>
</head>
<body>

<div class="navbar">
    <div class="logo">SIN // ENTERPRISE SOC</div>
    <div style="display:flex; gap:12px;">
        <input type="text" id="subnet" value="192.168.30" style="background:var(--bg); border:1px solid var(--border); color:white; padding:4px 12px; font-family:var(--font-mono); border-radius:4px;">
        <button class="btn btn-scan" onclick="triggerScan()">Active Scan</button>
    </div>
</div>

<div class="metrics">
    <div class="metric-box"><div class="m-title">Total Endpoints</div><div class="m-value" id="stat-total">-</div></div>
    <div class="metric-box"><div class="m-title">Critical Assets</div><div class="m-value" id="stat-crit" style="color:var(--red)">-</div></div>
    <div class="metric-box"><div class="m-title">Exploited (KEV)</div><div class="m-value" id="stat-kev" style="color:var(--orange)">-</div></div>
    <div class="metric-box"><div class="m-title">Quarantined</div><div class="m-value" id="stat-iso" style="color:var(--blue)">-</div></div>
</div>

<div class="container">
    <div class="table-area" id="table-wrap"></div>
</div>

<script>
const API = 'REPLACE_API_URL';
const KEY = 'REPLACE_API_KEY';

async function apiCall(endpoint, method='GET', body=null) {
    const opts = { method, headers: { 'X-API-Key': KEY, 'Content-Type': 'application/json' } };
    if(body) opts.body = JSON.stringify(body);
    return fetch(`${API}${endpoint}`, opts).then(r => r.json());
}

async function triggerScan() {
    const sub = document.getElementById('subnet').value;
    await apiCall('/scan/trigger', 'POST', {subnet: sub});
    alert('Scan Initiated on ' + sub);
}

async function quarantine(ip) {
    if(confirm(`Isolate ${ip} from network?`)) {
        await apiCall(`/agent/isolate/${ip}`, 'POST');
        refresh();
    }
}

function refresh() {
    apiCall('/devices').then(devs => {
        let kevCount = 0;
        let critCount = 0;
        let isoCount = 0;
        
        let html = `<table><thead><tr><th>Endpoint</th><th>Identity & Firmware</th><th>Risk Verdict</th><th>Controls</th></tr></thead><tbody>`;
        
        devs.forEach(d => {
            if(d.status === 'mitigated') isoCount++;
            if(d.risk_level === 'CRITICAL') critCount++;
            
            // Check for KEVs
            const hasKev = d.vulnerabilities.some(v => v.in_kev);
            if(hasKev) kevCount++;

            html += `<tr>
                <td>
                    <div class="ip-col">${d.ip_address}</div>
                    <div class="mac-col">${d.mac_address}</div>
                </td>
                <td>
                    <div style="font-weight:600;">${d.manufacturer} ${d.model || ''}</div>
                    ${d.firmware && d.firmware !== 'Unknown' ? `<div class="fw-badge">FW: ${d.firmware}</div>` : ''}
                    ${d.serial_number && d.serial_number !== 'N/A' ? `<div class="fw-badge">SN: ${d.serial_number}</div>` : ''}
                    ${d.telemetry && d.telemetry.cpu_usage ? `<div class="telemetry-box">CPU: ${d.telemetry.cpu_usage} | TEMP: ${d.telemetry.temperature || 'N/A'}</div>` : ''}
                </td>
                <td>
                    <strong style="color:${d.risk_level==='CRITICAL'?'var(--red)':'var(--orange)'}">${d.risk_level} (${d.risk_score})</strong>
                </td>
                <td>
                    ${d.status === 'mitigated' 
                        ? `<span style="color:var(--blue);font-weight:600;font-size:11px;">ISOLATED</span>`
                        : `<button class="btn btn-iso" onclick="quarantine('${d.ip_address}')">QUARANTINE</button>`}
                </td>
            </tr>`;

            // Vulnerability details drop-down
            if(d.vulnerabilities && d.vulnerabilities.length > 0) {
                html += `<tr class="vuln-row"><td colspan="4" style="padding-top:0;">`;
                d.vulnerabilities.forEach(v => {
                    html += `<div class="vuln-card">
                        <strong style="color:var(--text);">${v.type || v.cve}</strong>
                        ${v.in_kev ? '<span class="kev-badge">CISA KEV MATCH</span>' : ''}
                        ${v.epss > 0.1 ? `<span class="fw-badge" style="background:var(--orange);color:black;">EPSS: ${(v.epss*100).toFixed(1)}%</span>` : ''}
                        <div style="color:var(--text-dim); margin-top:4px;">${v.description}</div>
                    </div>`;
                });
                html += `</td></tr>`;
            }
        });
        
        html += `</tbody></table>`;
        document.getElementById('table-wrap').innerHTML = html;
        
        document.getElementById('stat-total').innerText = devs.length;
        document.getElementById('stat-crit').innerText = critCount;
        document.getElementById('stat-kev').innerText = kevCount;
        document.getElementById('stat-iso').innerText = isoCount;
    });
}

refresh();
setInterval(refresh, 10000); // Auto-refresh every 10s
</script>
</body>
</html>
""".replace("REPLACE_API_URL", API_URL).replace("REPLACE_API_KEY", API_KEY)

components.html(SOC_HTML, height=1000, scrolling=True)
