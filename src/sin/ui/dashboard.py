import streamlit as st
import streamlit.components.v1 as components
import os

# --- ENTERPRISE CONFIG ---
API_URL = "http://localhost:8000"
# Fallback to the verified key from your logs if environment variable is missing
API_KEY = os.getenv("SIN_API_KEY", "a634fd2d20eb8dd013eab32bdbf9529694abb5e46a35dd92d531faf34f1f0291")

st.set_page_config(page_title="SIN // ENTERPRISE EDR", layout="wide", page_icon="⚡")

# Eliminate Streamlit padding and headers for a native SOC feel
st.markdown("""
    <style>
        #MainMenu, footer, header {visibility: hidden;}
        .block-container {padding: 0px !important; max-width: 100% !important;}
        iframe {border: none;}
    </style>
""", unsafe_allow_html=True)

# --- ADVANCED SOC INTERFACE ---
# Incorporates real-time WebSockets, CVE deep-linking, and EDR Quarantine toggles
SOC_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
<style>
/* CSS Reset & Enterprise SOC Variables */
*{margin:0;padding:0;box-sizing:border-box;}
:root{
  --bg:#080a0f;--surface:#0f121a;--surface-hover:#161b26;
  --border:#1e2533;--accent:#3b82f6;--accent-dim:rgba(59,130,246,0.1);
  --text-main:#f1f5f9;--text-dim:#94a3b8;
  --red:#f43f5e;--orange:#fb923c;--green:#10b981;
  --font-mono:'IBM Plex Mono',monospace;--font-sans:'Inter',sans-serif;
}
body{font-family:var(--font-sans);background:var(--bg);color:var(--text-main);height:100vh;display:flex;overflow:hidden;}

/* Sidebar - High Density */
.sidebar{width:240px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;}
.sidebar-header{padding:24px;border-bottom:1px solid var(--border);}
.logo{font-size:18px;font-weight:600;letter-spacing:2px;display:flex;align-items:center;gap:8px;}
.pulse{width:8px;height:8px;background:var(--red);border-radius:50%;animation:p 2s infinite;}
@keyframes p{0%{box-shadow:0 0 0 0 rgba(244,63,94,0.4)}100%{box-shadow:0 0 0 8px transparent}}

/* Main Layout */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;}
.topbar{height:60px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 24px;background:var(--surface);}

/* Metrics Grid - High Impact */
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);border-bottom:1px solid var(--border);}
.metric-tile{background:var(--surface);padding:20px 24px;}
.m-label{font-size:10px;text-transform:uppercase;color:var(--text-dim);letter-spacing:1px;margin-bottom:8px;}
.m-value{font-size:24px;font-family:var(--font-mono);font-weight:400;}

/* Content Panels */
.dashboard-grid{flex:1;display:grid;grid-template-columns:1fr 350px;overflow:hidden;}
.asset-registry{overflow-y:auto;border-right:1px solid var(--border);padding:24px;}
.alert-stream{background:#0b0e14;display:flex;flex-direction:column;}
.panel-head{padding:16px;border-bottom:1px solid var(--border);font-size:12px;font-weight:600;text-transform:uppercase;color:var(--text-dim);}

/* Actionable Asset Table */
table{width:100%;border-collapse:collapse;margin-top:16px;}
th{text-align:left;font-size:10px;color:var(--text-dim);padding:12px;text-transform:uppercase;border-bottom:1px solid var(--border);}
tr{border-bottom:1px solid var(--border);cursor:pointer;}
tr:hover{background:var(--surface-hover);}
td{padding:14px 12px;font-size:13px;}
.td-ip{font-family:var(--font-mono);color:var(--accent);}

/* EDR Controls */
.btn-quarantine{padding:4px 8px;border-radius:4px;border:1px solid var(--red);color:var(--red);background:transparent;font-size:10px;cursor:pointer;font-weight:600;}
.btn-quarantine:hover{background:var(--red);color:white;}
.btn-restore{padding:4px 8px;border-radius:4px;border:1px solid var(--green);color:var(--green);background:transparent;font-size:10px;cursor:pointer;font-weight:600;}

/* CVE Redirection */
.cve-link{color:var(--accent);text-decoration:none;font-family:var(--font-mono);font-size:11px;}
.cve-link:hover{text-decoration:underline;}

/* Real-time Alerts */
.alert-card{padding:12px 16px;border-bottom:1px solid var(--border);font-size:12px;animation:slideIn 0.3s ease-out;}
@keyframes slideIn{from{transform:translateX(100%)}to{transform:translateX(0)}}
.alert-crit{border-left:4px solid var(--red);}
.alert-warn{border-left:4px solid var(--orange);}
</style>
</head>
<body>

<nav class="sidebar">
    <div class="sidebar-header">
        <div class="logo"><div class="pulse"></div> SIN ENTERPRISE</div>
        <div style="font-size:10px;color:var(--text-dim);margin-top:4px;">SOC/EDR COMMAND v2.1</div>
    </div>
    <div style="padding:16px;flex:1;">
        <div style="font-size:9px;color:var(--text-dim);margin-bottom:12px;">SYSTEM MONITOR</div>
        <div style="color:var(--accent);font-size:13px;font-weight:600;padding:8px 0;">Asset Intelligence</div>
        <div style="color:var(--text-dim);font-size:13px;padding:8px 0;">Threat Hunting</div>
    </div>
    <div style="padding:16px;border-top:1px solid var(--border);font-size:11px;color:var(--green);">
        ● CORE NODE ACTIVE
    </div>
</nav>

<div class="main">
    <div class="topbar">
        <span style="font-size:14px;font-weight:600;">ACTIVE THREAT LANDSCAPE</span>
        <div style="display:flex;gap:12px;">
            <input id="subnet" value="192.168.30" style="background:var(--bg);border:1px solid var(--border);color:white;padding:6px 12px;border-radius:6px;font-family:var(--font-mono);font-size:12px;">
            <button onclick="triggerScan()" style="background:var(--accent);border:none;color:white;padding:6px 16px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;">FORCE SCAN</button>
        </div>
    </div>

    <div class="metrics">
        <div class="metric-tile"><div class="m-label">Endpoints</div><div class="m-value" id="stat-total">-</div></div>
        <div class="metric-tile"><div class="m-label">Critical</div><div class="m-value" style="color:var(--red)" id="stat-crit">-</div></div>
        <div class="metric-tile"><div class="m-label">Vulnerable</div><div class="m-value" style="color:var(--orange)" id="stat-vuln">-</div></div>
        <div class="metric-tile"><div class="m-label">Active Quarantines</div><div class="m-value" style="color:var(--accent)" id="stat-iso">-</div></div>
    </div>

    <div class="dashboard-grid">
        <div class="asset-registry">
            <div id="table-wrap"></div>
        </div>
        <div class="alert-stream">
            <div class="panel-head">Real-time Security Events</div>
            <div id="alert-list" style="overflow-y:auto;flex:1;"></div>
        </div>
    </div>
</div>

<script>
const API = 'REPLACE_API_URL';
const KEY = 'REPLACE_API_KEY';
const WS_URL = 'ws://localhost:8000/ws/events';

// --- AUTHENTICATED FETCH ---
async function apiCall(endpoint, method='GET', body=null) {
    const opts = { method, headers: { 'X-API-Key': KEY, 'Content-Type': 'application/json' } };
    if(body) opts.body = JSON.stringify(body);
    return fetch(`${API}${endpoint}`, opts).then(r => r.json());
}

// --- EDR ACTIONS ---
async function quarantine(ip) {
    if(!confirm(`Confirm Network Quarantine for ${ip}?`)) return;
    await apiCall(`/agent/isolate/${ip}`, 'POST');
    pushAlert('SYSTEM', `Isolation deployed to ${ip}`, 'CRITICAL');
    refresh();
}

async function restore(ip) {
    await apiCall(`/agent/lift/${ip}`, 'POST');
    pushAlert('SYSTEM', `Isolation lifted for ${ip}`, 'INFO');
    refresh();
}

// --- UI RENDERING ---
function refresh() {
    apiCall('/devices').then(renderTable);
    apiCall('/stats').then(s => {
        document.getElementById('stat-total').innerText = s.total_devices || 0;
        document.getElementById('stat-crit').innerText = s.critical || 0;
        document.getElementById('stat-vuln').innerText = s.vulnerable || 0;
        document.getElementById('stat-iso').innerText = s.isolated || 0;
    });
}

function renderTable(devs) {
    const wrap = document.getElementById('table-wrap');
    if(!devs || devs.length === 0) {
        wrap.innerHTML = '<div style="color:var(--text-dim);text-align:center;padding:40px;">No Assets Detected</div>';
        return;
    }
    wrap.innerHTML = `<table>
        <thead><tr><th>IP Endpoint</th><th>Fingerprint</th><th>Risk Level</th><th>Actions</th></tr></thead>
        <tbody>
            ${devs.map(d => {
                const isIso = d.status === 'mitigated';
                return `<tr>
                    <td class="td-ip">${d.ip_address}</td>
                    <td><span style="color:var(--text-dim)">${d.manufacturer || 'Generic'}</span><br><small>${d.os_family || ''}</small></td>
                    <td><span style="color:${d.risk_level==='CRITICAL'? 'var(--red)' : 'var(--orange)'}">${d.risk_level}</span></td>
                    <td>
                        ${isIso ? 
                            `<button class="btn-restore" onclick="restore('${d.ip_address}')">LIFT RESTRICTION</button>` : 
                            `<button class="btn-quarantine" onclick="quarantine('${d.ip_address}')">QUARANTINE</button>`
                        }
                    </td>
                </tr>
                ${d.vulnerabilities.length > 0 ? `<tr><td colspan="4" style="padding:0 12px 14px 12px; background:rgba(255,255,255,0.02)">
                    ${d.vulnerabilities.map(v => `
                        <div style="font-size:11px; margin-top:4px;">
                            <span style="color:var(--orange)">[!]</span> ${v.description} 
                            ${v.cve ? `<a href="https://nvd.nist.gov/vuln/detail/${v.cve}" target="_blank" class="cve-link">${v.cve}</a>` : ''}
                        </div>
                    `).join('')}
                </td></tr>` : ''}`;
            }).join('')}
        </tbody>
    </table>`;
}

// --- REAL-TIME ENGINE ---
function pushAlert(source, msg, sev) {
    const list = document.getElementById('alert-list');
    const card = document.createElement('div');
    card.className = `alert-card ${sev==='CRITICAL' ? 'alert-crit' : 'alert-warn'}`;
    card.innerHTML = `<div style="font-family:var(--font-mono);font-size:10px;color:var(--text-dim);">${new Date().toLocaleTimeString()} - ${source}</div><div>${msg}</div>`;
    list.prepend(card);
}

function connectWS() {
    const ws = new WebSocket(WS_URL);
    ws.onmessage = (e) => {
        const data = JSON.parse(e.data);
        if(data.kind === 'scan_complete') refresh();
        if(data.kind === 'event') pushAlert(data.ip_address, data.description, data.severity);
    };
}

async function triggerScan() {
    const subnet = document.getElementById('subnet').value;
    await apiCall('/scan/trigger', 'POST', { subnet });
    pushAlert('SCANNER', `Scanning subnet ${subnet}.0/24...`, 'INFO');
}

refresh();
connectWS();
setInterval(refresh, 30000);
</script>
</body>
</html>
""".replace("REPLACE_API_URL", API_URL).replace("REPLACE_API_KEY", API_KEY)

components.html(SOC_HTML, height=900, scrolling=False)
