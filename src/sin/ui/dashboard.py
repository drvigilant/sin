import streamlit as st
import streamlit.components.v1 as components
import os

# --- AUTH & CONFIG ---
# These are used by your Windows browser to talk to the API
API_URL = "http://127.0.0.1:8000"
API_KEY = os.getenv("SIN_API_KEY", "a634fd2d20eb8dd013eab32bdbf9529694abb5e46a35dd92d531faf34f1f0291")

st.set_page_config(
    page_title="SIN — Shadows In The Network",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Hide Streamlit UI elements for a professional SOC look
st.markdown("""
    <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {visibility: hidden;}
        .block-container {padding: 0px !important; max-width: 100% !important;}
        iframe {border: none;}
    </style>
""", unsafe_allow_html=True)

# --- VETERAN HTML (Standard string to avoid SyntaxErrors) ---
# We use REPLACE_API_URL and REPLACE_API_KEY as placeholders
RAW_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SIN — Shadows In The Network</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;}
:root{
  --bg:#0b0e14;--surface:#111520;--surface2:#181d2e;
  --border:rgba(255,255,255,0.06);--border2:rgba(255,255,255,0.12);
  --text:#e2e8f0;--muted:#64748b;--dim:#2d3748;
  --accent:#3b82f6;--accent-dim:rgba(59,130,246,0.12);
  --red:#ef4444;--red-dim:rgba(239,68,68,0.12);
  --orange:#f97316;--orange-dim:rgba(249,115,22,0.12);
  --green:#22c55e;--green-dim:rgba(34,197,94,0.12);
  --yellow:#eab308;--yellow-dim:rgba(234,179,8,0.12);
  --mono:'IBM Plex Mono',monospace;--sans:'DM Sans',sans-serif;
}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;overflow:hidden;}
.sidebar{width:220px;min-width:220px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;height:100vh;}
.sidebar-logo{padding:20px 20px 16px;border-bottom:1px solid var(--border);}
.logo-mark{display:flex;align-items:center;gap:10px;margin-bottom:4px;}
.logo-pulse{width:8px;height:8px;border-radius:50%;background:var(--red);animation:pulse 2s infinite;}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(239,68,68,0.4)}50%{opacity:.7;box-shadow:0 0 0 6px rgba(239,68,68,0)}}
.logo-text{font-size:15px;font-weight:500;letter-spacing:.12em;color:var(--text);}
.logo-sub{font-size:10px;color:var(--muted);letter-spacing:.06em;font-family:var(--mono);}
.sidebar-nav{padding:12px 8px;flex:1;}
.nav-section{font-size:9px;font-weight:500;letter-spacing:.1em;color:var(--muted);padding:16px 12px 6px;text-transform:uppercase;}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;cursor:pointer;font-size:13px;color:var(--muted);transition:all .15s;margin-bottom:2px;border:none;background:none;width:100%;text-align:left;font-family:var(--sans);}
.nav-item:hover{background:var(--surface2);color:var(--text);}
.nav-item.active{background:var(--accent-dim);color:var(--accent);}
.sidebar-footer{padding:16px;border-top:1px solid var(--border);}
.status-chip{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--green-dim);border-radius:8px;border:1px solid rgba(34,197,94,0.2);}
.status-dot{width:6px;height:6px;border-radius:50%;background:var(--green);}
.status-text{font-size:11px;color:var(--green);font-weight:500;}
.ai-chip{display:flex;align-items:center;gap:8px;padding:6px 12px;border-radius:8px;border:1px solid var(--border);margin-top:8px;font-size:10px;color:var(--muted);}
.ai-dot{width:6px;height:6px;border-radius:50%;background:var(--muted);}
.ai-dot.online{background:var(--accent);}
.main{flex:1;display:flex;flex-direction:column;height:100vh;overflow:hidden;}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:0 24px;height:56px;border-bottom:1px solid var(--border);flex-shrink:0;}
.topbar-title{font-size:14px;font-weight:500;}
.topbar-right{display:flex;align-items:center;gap:10px;}
.last-updated{font-size:11px;color:var(--muted);font-family:var(--mono);}
.scanning-indicator{font-size:11px;color:var(--yellow);font-family:var(--mono);display:none;animation:blink 1s infinite;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.scan-btn{display:flex;align-items:center;gap:6px;padding:7px 14px;background:var(--accent);border-radius:8px;border:none;color:#fff;font-size:12px;font-weight:500;cursor:pointer;font-family:var(--sans);transition:opacity .15s;}
.scan-btn:hover{opacity:.85;}
.scan-btn:disabled{opacity:.5;cursor:not-allowed;}
.subnet-input{background:var(--surface2);border:1px solid var(--border2);border-radius:8px;padding:7px 12px;color:var(--text);font-size:12px;font-family:var(--mono);width:130px;}
.subnet-input:focus{outline:none;border-color:var(--accent);}
.content{flex:1;overflow-y:auto;padding:24px;}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px;}
.metric-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 20px;}
.metric-label{font-size:10px;font-weight:500;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:10px;}
.metric-value{font-size:28px;font-weight:300;font-family:var(--mono);color:var(--text);line-height:1;}
.metric-value.red{color:var(--red);}
.metric-value.green{color:var(--green);}
.metric-value.orange{color:var(--orange);}
.metric-sub{font-size:10px;color:var(--muted);margin-top:6px;font-family:var(--mono);}
.panels{display:grid;grid-template-columns:1fr 320px;gap:16px;margin-bottom:24px;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;}
.panel-header{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--border);}
.panel-title{font-size:12px;font-weight:500;letter-spacing:.04em;}
.panel-badge{font-size:10px;font-family:var(--mono);color:var(--muted);background:var(--surface2);padding:3px 8px;border-radius:20px;}
.toolbar{display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid var(--border);}
.search-wrap{flex:1;position:relative;}
.search-input{width:100%;background:var(--surface2);border:1px solid var(--border2);border-radius:8px;padding:7px 12px 7px 32px;color:var(--text);font-size:12px;font-family:var(--sans);}
.search-input:focus{outline:none;border-color:var(--accent);}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);width:14px;height:14px;}
.filter-select{background:var(--surface2);border:1px solid var(--border2);border-radius:8px;padding:7px 10px;color:var(--muted);font-size:12px;font-family:var(--sans);cursor:pointer;}
table{width:100%;border-collapse:collapse;}
thead th{font-size:10px;font-weight:500;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);padding:10px 14px;text-align:left;border-bottom:1px solid var(--border);}
tbody tr{border-bottom:1px solid var(--border);cursor:pointer;transition:background .1s;}
tbody tr:hover{background:var(--surface2);}
tbody tr.selected{background:rgba(59,130,246,0.06);border-left:2px solid var(--accent);}
tbody td{padding:11px 14px;font-size:12px;}
.td-ip{font-family:var(--mono);font-size:11px;color:var(--accent);}
.td-mono{font-family:var(--mono);font-size:11px;color:var(--muted);}
.device-icon{width:28px;height:28px;border-radius:7px;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;}
.icon-camera{background:rgba(239,68,68,0.15);}
.icon-router{background:rgba(34,197,94,0.15);}
.icon-pc{background:rgba(59,130,246,0.15);}
.icon-iot{background:rgba(234,179,8,0.15);}
.icon-unknown{background:var(--surface2);}
.vendor-cell{display:flex;align-items:center;gap:8px;}
.badge{display:inline-block;font-size:10px;font-weight:500;padding:2px 8px;border-radius:20px;font-family:var(--mono);}
.badge-critical{background:var(--red-dim);color:var(--red);border:1px solid rgba(239,68,68,0.2);}
.badge-high{background:var(--orange-dim);color:var(--orange);border:1px solid rgba(249,115,22,0.2);}
.badge-medium{background:var(--accent-dim);color:var(--accent);border:1px solid rgba(59,130,246,0.2);}
.badge-low{background:var(--green-dim);color:var(--green);border:1px solid rgba(34,197,94,0.2);}
.badge-clean{background:var(--surface2);color:var(--muted);border:1px solid var(--border2);}
.port-tag{display:inline-block;font-size:10px;font-family:var(--mono);background:var(--surface2);color:var(--muted);border:1px solid var(--border2);border-radius:4px;padding:1px 6px;margin:1px;}
.detail-row{display:none;}
.detail-row.open{display:table-row;}
.detail-inner{padding:16px 18px;background:rgba(59,130,246,0.03);display:grid;grid-template-columns:1fr 1fr;gap:16px;}
.detail-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px;}
.detail-card h4{font-size:10px;font-weight:500;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:10px;}
.kv{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--border);font-size:11.5px;}
.kv:last-child{border:none;}
.kv-key{color:var(--muted);}
.kv-val{font-family:var(--mono);font-size:11px;text-align:right;max-width:200px;overflow:hidden;text-overflow:ellipsis;}
.vuln-item{padding:8px 10px;border-radius:8px;margin-bottom:6px;border:1px solid var(--border);border-left:3px solid var(--muted);}
.vuln-item.CRITICAL{border-left-color:var(--red);}
.vuln-item.HIGH{border-left-color:var(--orange);}
.vuln-item.MEDIUM{border-left-color:var(--accent);}
.vuln-item.LOW{border-left-color:var(--green);}
.vuln-type{font-size:11.5px;font-weight:500;margin-bottom:3px;}
.vuln-desc{font-size:11px;color:var(--muted);line-height:1.5;}
.vuln-cve{font-size:10px;font-family:var(--mono);color:var(--accent);margin-top:3px;}
.ai-audit-btn{display:flex;align-items:center;gap:5px;padding:5px 10px;background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.25);border-radius:6px;color:var(--accent);font-size:11px;cursor:pointer;font-family:var(--sans);margin-top:8px;}
.ai-audit-btn:hover{background:rgba(59,130,246,0.2);}
.ai-audit-btn:disabled{opacity:.5;cursor:not-allowed;}
.ai-result{margin-top:8px;padding:10px;background:var(--surface2);border-radius:8px;font-size:11px;color:var(--muted);border:1px solid var(--border);}
.events-list{max-height:420px;overflow-y:auto;}
.event-item{display:flex;gap:10px;padding:10px 14px;border-bottom:1px solid var(--border);align-items:flex-start;}
.event-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0;margin-top:4px;}
.event-dot.WARNING{background:var(--orange);}
.event-dot.CRITICAL{background:var(--red);}
.event-dot.INFO{background:var(--accent);}
.event-body{flex:1;min-width:0;}
.event-ip{font-size:11px;font-family:var(--mono);color:var(--accent);margin-bottom:2px;}
.event-desc{font-size:11px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.event-time{font-size:10px;font-family:var(--mono);color:var(--dim);flex-shrink:0;}
.empty{text-align:center;padding:48px;color:var(--muted);font-size:13px;}
::-webkit-scrollbar{width:4px;height:4px;}
::-webkit-scrollbar-thumb{background:var(--dim);border-radius:2px;}
.toast{position:fixed;bottom:24px;right:24px;background:var(--surface);border:1px solid var(--border2);border-radius:10px;padding:12px 16px;font-size:12px;font-family:var(--mono);z-index:999;display:none;}
.toast.show{display:block;}
</style>
</head>
<body>
<nav class="sidebar">
  <div class="sidebar-logo">
    <div class="logo-mark"><div class="logo-pulse"></div><span class="logo-text">SIN</span></div>
    <div class="logo-sub">SHADOWS IN THE NETWORK</div>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section">Monitor</div>
    <button class="nav-item active" onclick="showPage('dashboard',this)">
      <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1" stroke-width="1.5"/><rect x="14" y="3" width="7" height="7" rx="1" stroke-width="1.5"/><rect x="3" y="14" width="7" height="7" rx="1" stroke-width="1.5"/><rect x="14" y="14" width="7" height="7" rx="1" stroke-width="1.5"/></svg>
      Dashboard
    </button>
    <button class="nav-item" onclick="showPage('assets',this)">
      <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3" stroke-width="1.5"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2" stroke-width="1.5" stroke-linecap="round"/></svg>
      Asset Registry
    </button>
    <button class="nav-item" onclick="showPage('threats',this)">
      <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" stroke-width="1.5"/><line x1="12" y1="9" x2="12" y2="13" stroke-width="1.5"/><line x1="12" y1="17" x2="12.01" y2="17" stroke-width="1.5"/></svg>
      Threat Events
    </button>
  </div>
  <div class="sidebar-footer">
    <div class="status-chip"><div class="status-dot"></div><span class="status-text">System Online</span></div>
    <div class="ai-chip" id="ai-status-chip">
      <div class="ai-dot" id="ai-dot"></div>
      <span id="ai-status-text">Ollama: checking...</span>
    </div>
  </div>
</nav>

<div class="main">
  <div class="topbar">
    <span class="topbar-title" id="page-title">Dashboard</span>
    <div class="topbar-right">
      <span class="scanning-indicator" id="scanning-ind">● SCANNING</span>
      <span class="last-updated" id="last-updated">–</span>
      <input class="subnet-input" id="subnet-input" value="192.168.30">
      <button class="scan-btn" id="scan-btn" onclick="triggerScan()">→ Scan Now</button>
    </div>
  </div>
  <div class="content" id="content"><div class="empty">Loading...</div></div>
</div>
<div class="toast" id="toast"></div>

<script>
// --- AUTH CONFIG ---
const API = 'REPLACE_API_URL'; 
const AUTH_HEADERS = { 'X-API-Key': 'REPLACE_API_KEY' };

let allDevices=[], allEvents=[], stats={}, currentPage='dashboard';
let scanPolling=null;

// Authenticated Fetch Wrapper
async function secureFetch(url, options = {}) {
  options.headers = { ...options.headers, ...AUTH_HEADERS };
  return fetch(url, options);
}

async function fetchAll() {
  try {
    const [d,e,s] = await Promise.all([
      secureFetch(`${API}/devices`).then(r=>r.json()),
      secureFetch(`${API}/events`).then(r=>r.json()),
      secureFetch(`${API}/stats`).then(r=>r.json()),
    ]);
    allDevices=Array.isArray(d)?d:[];
    allEvents=Array.isArray(e)?e:[];
    stats=s||{};
    document.getElementById('last-updated').textContent='updated '+new Date().toLocaleTimeString();
    renderPage();
  } catch(e) {
    document.getElementById('content').innerHTML=`<div class="empty">Cannot reach API at ${API}<br><small>${e.message}</small></div>`;
  }
}

async function checkOllama() {
  try {
    const r = await secureFetch(`${API}/ai/status`);
    const d = await r.json();
    const dot = document.getElementById('ai-dot');
    const txt = document.getElementById('ai-status-text');
    if(d.online) {
      dot.classList.add('online');
      txt.textContent = `Ollama: ${d.models[0]||'online'}`;
    } else {
      dot.classList.remove('online');
      txt.textContent = 'Ollama: offline';
    }
  } catch(e) {
    document.getElementById('ai-status-text').textContent='Ollama: offline';
  }
}

async function triggerScan() {
  const subnet = document.getElementById('subnet-input').value||'192.168.30';
  const btn = document.getElementById('scan-btn');
  const ind = document.getElementById('scanning-ind');
  btn.disabled=true; btn.textContent='Scanning...';
  ind.style.display='block';

  try {
    await secureFetch(`${API}/scan/trigger`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({subnet})});
    showToast('Scan started for '+subnet);
    scanPolling = setInterval(async()=>{
      try {
        const r = await secureFetch(`${API}/scan/status`);
        const d = await r.json();
        if(!d.scanning) {
          clearInterval(scanPolling);
          btn.disabled=false; btn.textContent='→ Scan Now';
          ind.style.display='none';
          await fetchAll();
          showToast('Scan complete — dashboard updated');
        }
      } catch(e){ clearInterval(scanPolling); btn.disabled=false; btn.textContent='→ Scan Now'; ind.style.display='none'; }
    }, 3000);
  } catch(e) {
    btn.disabled=false; btn.textContent='→ Scan Now'; ind.style.display='none';
    showToast('Cannot reach API');
  }
}

function showPage(page,btn) {
  currentPage=page;
  document.querySelectorAll('.nav-item').forEach(b=>b.classList.remove('active'));
  if(btn) btn.classList.add('active');
  const titles={dashboard:'Dashboard',assets:'Asset Registry',threats:'Threat Events'};
  document.getElementById('page-title').textContent=titles[page]||page;
  renderPage();
}

function renderPage() {
  if(currentPage==='dashboard') renderDashboard();
  else if(currentPage==='assets') renderAssets();
  else if(currentPage==='threats') renderThreats();
}

function renderDashboard() {
  const byVendor={};
  allDevices.forEach(d=>{const v=d.manufacturer||d.vendor||'Unknown';byVendor[v]=(byVendor[v]||0)+1;});
  const topV=Object.entries(byVendor).sort((a,b)=>b[1]-a[1]).slice(0,6);
  const maxV=topV[0]?.[1]||1;
  const vuln=allDevices.filter(d=>d.vulnerabilities&&d.vulnerabilities.length>0);

  document.getElementById('content').innerHTML=`
    <div class="metrics">
      <div class="metric-card"><div class="metric-label">Total Assets</div><div class="metric-value">${stats.total_devices||allDevices.length}</div><div class="metric-sub">latest scan</div></div>
      <div class="metric-card"><div class="metric-label">Vulnerable</div><div class="metric-value orange">${stats.vulnerable||vuln.length}</div><div class="metric-sub">require attention</div></div>
      <div class="metric-card"><div class="metric-label">Critical</div><div class="metric-value red">${stats.critical||0}</div><div class="metric-sub">immediate action</div></div>
      <div class="metric-card"><div class="metric-label">Clean</div><div class="metric-value green">${stats.clean||0}</div><div class="metric-sub">no issues</div></div>
    </div>
    <div class="panels">
      <div class="panel">
        <div class="panel-header"><span class="panel-title">Vendor Distribution</span><span class="panel-badge">${Object.keys(byVendor).length} vendors</span></div>
        <div style="padding:16px 18px;">
          ${topV.map(([v,c])=>`<div style="margin-bottom:10px;"><div style="display:flex;justify-content:space-between;margin-bottom:4px;"><span style="font-size:12px;">${v}</span><span style="font-size:11px;font-family:var(--mono);color:var(--muted);">${c}</span></div><div style="height:4px;background:var(--surface2);border-radius:2px;"><div style="height:4px;background:var(--accent);border-radius:2px;width:${Math.round(c/maxV*100)}%;"></div></div></div>`).join('')}
        </div>
      </div>
      <div class="panel">
        <div class="panel-header"><span class="panel-title">Recent Events</span><span class="panel-badge">${allEvents.length} total</span></div>
        <div class="events-list">
          ${allEvents.slice(0,8).map(e=>`<div class="event-item"><div class="event-dot ${e.severity}"></div><div class="event-body"><div class="event-ip">${e.ip_address}</div><div class="event-desc">${e.description}</div></div><div class="event-time">${e.timestamp?new Date(e.timestamp).toLocaleTimeString():''}</div></div>`).join('')||'<div class="empty">No events yet</div>'}
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><span class="panel-title">Vulnerable Assets</span><span class="panel-badge">${vuln.length} devices</span></div>
      ${vuln.length?buildTable(vuln):'<div class="empty">No vulnerabilities detected</div>'}
    </div>`;
}

function renderAssets(filter='',sevF='',venF='') {
  let data=allDevices.filter(d=>{
    if(filter){const q=filter.toLowerCase();if(![d.ip_address,d.manufacturer||'',d.vendor||'',d.os_family||'',d.hostname||'',d.mac_address||''].join(' ').toLowerCase().includes(q))return false;}
    if(sevF==='vulnerable'&&(!d.vulnerabilities||!d.vulnerabilities.length))return false;
    if(sevF==='clean'&&d.vulnerabilities&&d.vulnerabilities.length)return false;
    if(venF&&(d.manufacturer||d.vendor||'Unknown')!==venF)return false;
    return true;
  });
  const vendors=[...new Set(allDevices.map(d=>d.manufacturer||d.vendor||'Unknown'))].sort();
  document.getElementById('content').innerHTML=`
    <div class="panel">
      <div class="panel-header"><span class="panel-title">Asset Registry</span><span class="panel-badge">${data.length} / ${allDevices.length}</span></div>
      <div class="toolbar">
        <div class="search-wrap">
          <svg class="search-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8" stroke-width="1.5"/><path d="M21 21l-4.35-4.35" stroke-width="1.5"/></svg>
          <input class="search-input" id="asset-search" placeholder="Search IP, MAC, vendor, hostname..." value="${filter}" oninput="renderAssets(this.value,document.getElementById('sev-f').value,document.getElementById('ven-f').value)">
        </div>
        <select class="filter-select" id="sev-f" onchange="renderAssets(document.getElementById('asset-search').value,this.value,document.getElementById('ven-f').value)">
          <option value="" ${sevF===''?'selected':''}>All status</option>
          <option value="vulnerable" ${sevF==='vulnerable'?'selected':''}>Vulnerable</option>
          <option value="clean" ${sevF==='clean'?'selected':''}>Clean</option>
        </select>
        <select class="filter-select" id="ven-f" onchange="renderAssets(document.getElementById('asset-search').value,document.getElementById('sev-f').value,this.value)">
          <option value="">All vendors</option>
          ${vendors.map(v=>`<option value="${v}" ${venF===v?'selected':''}>${v}</option>`).join('')}
        </select>
      </div>
      ${data.length?buildTable(data):'<div class="empty">No assets match filter</div>'}
    </div>`;
}

function renderThreats() {
  document.getElementById('content').innerHTML=`
    <div class="panel">
      <div class="panel-header"><span class="panel-title">Security Event Timeline</span><span class="panel-badge">${allEvents.length} events</span></div>
      <div class="events-list" style="max-height:none;">
        ${allEvents.map(e=>`<div class="event-item"><div class="event-dot ${e.severity}"></div><div class="event-body"><div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;"><span class="event-ip">${e.ip_address}</span><span class="badge badge-${(e.severity||'clean').toLowerCase()}">${e.severity}</span><span style="font-size:10px;font-family:var(--mono);color:var(--muted);">${e.event_type}</span></div><div class="event-desc" style="white-space:normal;">${e.description}</div></div><div class="event-time">${e.timestamp?new Date(e.timestamp).toLocaleString():''}</div></div>`).join('')||'<div class="empty">No events</div>'}
      </div>
    </div>`;
}

function deviceIcon(d) {
  const v=(d.manufacturer||d.vendor||'').toLowerCase();
  const ports=d.open_ports||[];
  if(['hikvision','dahua','axis','vivotek','hanwha','reolink','amcrest'].some(x=>v.includes(x))||ports.includes(554)||ports.includes(8554))return['icon-camera','📷'];
  if(['ubiquiti','mikrotik','netgear','tp-link'].some(x=>v.includes(x)))return['icon-router','🔀'];
  if(ports.includes(1883)||ports.includes(5683))return['icon-iot','📡'];
  return['icon-unknown','❓'];
}

function topSev(vulns) {
  if(!vulns||!vulns.length)return null;
  for(const s of['CRITICAL','HIGH','MEDIUM','LOW'])if(vulns.some(v=>v.severity===s))return s;
  return null;
}

function buildTable(data) {
  return `<div style="overflow-x:auto;"><table>
    <thead><tr><th>IP Address</th><th>MAC</th><th>Hostname</th><th>Vendor</th><th>OS</th><th>Ports</th><th>Risk</th></tr></thead>
    <tbody>${data.map((d,i)=>{
      const [icls,ico]=deviceIcon(d);
      const sev=topSev(d.vulnerabilities);
      const badge=sev?`<span class="badge badge-${sev.toLowerCase()}">${sev}</span>${d.vulnerabilities.length>1?` <span style="font-size:10px;color:var(--muted);">${d.vulnerabilities.length}</span>`:''}` :`<span class="badge badge-clean">Clean</span>`;
      const ports=(d.open_ports||[]).slice(0,5).map(p=>`<span class="port-tag">${p}</span>`).join('')+((d.open_ports||[]).length>5?`<span style="font-size:10px;color:var(--muted);"> +${d.open_ports.length-5}</span>`:'');
      return `<tr onclick="toggleDetail(this,${i},'${d.ip_address}')">
        <td class="td-ip">${d.ip_address}</td>
        <td class="td-mono">${d.mac_address||'–'}</td>
        <td style="color:var(--muted);font-size:11.5px;">${d.hostname||'–'}</td>
        <td><div class="vendor-cell"><div class="device-icon ${icls}">${ico}</div><span style="font-size:12px;">${d.manufacturer||d.vendor||'Unknown'}</span></div></td>
        <td style="color:var(--muted);font-size:11.5px;">${d.os_family||'–'}</td>
        <td>${ports}</td>
        <td>${badge}</td>
      </tr>
      <tr class="detail-row" id="detail-${i}"><td colspan="7" style="padding:0;"><div class="detail-inner" id="detail-inner-${i}"></div></td></tr>`;
    }).join('')}</tbody></table></div>`;
}

function toggleDetail(row,idx,ip) {
  const dr=document.getElementById(`detail-${idx}`);
  const inner=document.getElementById(`detail-inner-${idx}`);
  const isOpen=dr.classList.contains('open');
  document.querySelectorAll('.detail-row.open').forEach(r=>r.classList.remove('open'));
  document.querySelectorAll('tbody tr.selected').forEach(r=>r.classList.remove('selected'));
  if(isOpen) return;
  dr.classList.add('open'); row.classList.add('selected');
  const d=allDevices.find(x=>x.ip_address===ip)||{};
  const vulns=d.vulnerabilities||[];
  inner.innerHTML=`
    <div class="detail-card">
      <h4>Asset Details</h4>
      ${[['IP Address',d.ip_address],['MAC Address',d.mac_address||'–'],['Hostname',d.hostname||'–'],['Manufacturer',d.manufacturer||d.vendor||'Unknown'],['OS / Type',d.os_family||'–'],['Open Ports',(d.open_ports||[]).join(', ')||'None'],['Status',d.status||'online']].map(([k,v])=>`<div class="kv"><span class="kv-key">${k}</span><span class="kv-val">${v}</span></div>`).join('')}
      <button class="ai-audit-btn" id="ai-btn-${idx}" onclick="runOllamaAudit('${ip}',${idx})">
        🤖 AI Audit (Ollama)
      </button>
      <div id="ai-result-${idx}" class="ai-result" style="display:none;"></div>
    </div>
    <div class="detail-card">
      <h4>Vulnerabilities (${vulns.length})</h4>
      ${vulns.length?vulns.map(v=>`<div class="vuln-item ${v.severity||''}"><div class="vuln-type">${v.type||'Finding'}</div><div class="vuln-desc">${v.description||''}</div>${v.cve?`<div class="vuln-cve">${v.cve}</div>`:''}</div>`).join(''):'<div style="color:var(--muted);font-size:12px;padding:8px 0;">No vulnerabilities detected.</div>'}
    </div>`;
}

async function runOllamaAudit(ip, idx) {
  const btn=document.getElementById(`ai-btn-${idx}`);
  const result=document.getElementById(`ai-result-${idx}`);
  const d=allDevices.find(x=>x.ip_address===ip)||{};
  btn.disabled=true; btn.textContent='🤖 Analysing...';
  result.style.display='block'; result.textContent='Asking Ollama...';
  try {
    const r=await secureFetch(`${API}/ai/audit`,{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ip_address:ip,open_ports:d.open_ports||[],vendor:d.manufacturer||d.vendor||'',os_family:d.os_family||'',hostname:d.hostname||'',vulnerabilities:d.vulnerabilities||[]})
    });
    const data=await r.json();
    if(data.error&&!data.findings.length){
      result.textContent='Ollama unavailable: '+data.error;
    } else if(!data.findings.length){
      result.textContent='✅ Ollama found no additional issues.';
    } else {
      result.innerHTML=data.findings.map(f=>`<div class="vuln-item ${f.severity||''}" style="margin-bottom:6px;"><div class="vuln-type"><span class="badge badge-${(f.severity||'low').toLowerCase()}">${f.severity}</span> ${f.type}</div><div class="vuln-desc">${f.description}</div></div>`).join('');
    }
    btn.textContent='🤖 Re-run Audit'; btn.disabled=false;
  } catch(e) {
    result.textContent='Error: '+e.message;
    btn.textContent='🤖 AI Audit (Ollama)'; btn.disabled=false;
  }
}

function showToast(msg) {
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),3000);
}

// --- BOOT ---
fetchAll();
checkOllama();
setInterval(fetchAll,30000);
setInterval(checkOllama,60000);
</script>
</body>
</html>
""".replace("REPLACE_API_URL", API_URL).replace("REPLACE_API_KEY", API_KEY)

# Render the page as a clean, standalone component
components.html(RAW_HTML, height=850, scrolling=True)
