"""
SIN Enterprise Dashboard  v3
Dark / Light theme toggle · Analytics · Alerts · Live Asset Table
"""
import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests, time, os, json, math

from sin.response.report import generate_pdf_report

API_URL = os.getenv("SIN_API_URL", "http://localhost:8000")

st.set_page_config(
    page_title="SIN — Shadows In The Network",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Theme state ───────────────────────────────────────────────────────────────
if "theme" not in st.session_state:
    st.session_state.theme = "dark"
if "active_tab" not in st.session_state:
    st.session_state.active_tab = "overview"

T = st.session_state.theme
IS_DARK = T == "dark"

# ── Theme tokens ──────────────────────────────────────────────────────────────
THEME = {
    "dark": {
        "bg":         "#0F1318",
        "bg2":        "#161C26",
        "bg3":        "#1E2535",
        "border":     "rgba(255,255,255,0.06)",
        "t1":         "#FFFFFF",
        "t2":         "#A0AABB",
        "t3":         "#556070",
        "sidebar_bg": "#0A0D12",
        "card_bg":    "#161C26",
        "plotly_bg":  "#161C26",
        "plotly_paper":"#0F1318",
        "plotly_font":"#A0AABB",
        "plotly_grid":"rgba(255,255,255,0.05)",
    },
    "light": {
        "bg":         "#F0F2F5",
        "bg2":        "#FFFFFF",
        "bg3":        "#E8EBF0",
        "border":     "rgba(0,0,0,0.07)",
        "t1":         "#0D1117",
        "t2":         "#4A5568",
        "t3":         "#8B9DB0",
        "sidebar_bg": "#FFFFFF",
        "card_bg":    "#FFFFFF",
        "plotly_bg":  "#FFFFFF",
        "plotly_paper":"#F0F2F5",
        "plotly_font":"#4A5568",
        "plotly_grid":"rgba(0,0,0,0.06)",
    },
}[T]

ACCENT = "#00AAFF"
DANGER = "#FF4757"
WARN   = "#FFA502"
SAFE   = "#2ED573"

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&display=swap');

*{{box-sizing:border-box;}}
:root{{
  --bg:{THEME['bg']};--bg2:{THEME['bg2']};--bg3:{THEME['bg3']};
  --border:{THEME['border']};--t1:{THEME['t1']};--t2:{THEME['t2']};--t3:{THEME['t3']};
  --accent:{ACCENT};--danger:{DANGER};--warn:{WARN};--safe:{SAFE};
  --mono:'IBM Plex Mono',monospace;--sans:'DM Sans',sans-serif;
}}
#MainMenu,footer{{visibility:hidden;height:0;}}
[data-testid="stHeader"],[data-testid="stDecoration"],.stDeployButton{{display:none!important;}}
[data-testid="stAppViewContainer"],.stApp{{background:var(--bg)!important;font-family:var(--sans)!important;}}
.main .block-container{{padding:1.4rem 2rem 3rem!important;max-width:100%!important;}}
[data-testid="stSidebar"]{{background:{THEME['sidebar_bg']}!important;
  border-right:1px solid var(--border)!important;min-width:220px!important;max-width:220px!important;}}
[data-testid="stSidebarContent"]{{padding:0!important;}}
section[data-testid="stSidebar"]>div:first-child{{padding:0!important;}}
[data-testid="stSidebar"] .stButton>button{{
  background:transparent!important;border:1px solid var(--border)!important;
  color:var(--t2)!important;font-family:var(--sans)!important;font-size:12px!important;
  width:100%!important;text-align:left!important;padding:7px 14px!important;
  border-radius:6px!important;margin-bottom:4px!important;transition:all 0.15s!important;}}
[data-testid="stSidebar"] .stButton>button:hover{{
  background:var(--bg3)!important;color:var(--t1)!important;
  border-color:rgba(0,170,255,0.3)!important;}}
[data-testid="stSidebar"] .stDownloadButton>button{{
  background:rgba(0,170,255,0.1)!important;border:1px solid rgba(0,170,255,0.3)!important;
  color:{ACCENT}!important;font-family:var(--sans)!important;font-size:12px!important;
  width:100%!important;padding:7px 14px!important;border-radius:6px!important;margin-top:4px!important;}}
hr{{border-color:var(--border)!important;margin:0!important;}}
.stSpinner>div{{border-top-color:{ACCENT}!important;}}
[data-testid="stSidebar"] [data-testid="stAlert"]{{
  background:var(--bg2)!important;border:1px solid var(--border)!important;
  font-family:var(--sans)!important;font-size:11px!important;
  padding:7px 10px!important;border-radius:5px!important;margin-top:5px!important;}}
[data-testid="element-container"] .stPlotlyChart{{background:transparent!important;}}
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────
def fetch_stats():
    try:
        r = requests.get(f"{API_URL}/stats", timeout=5)
        return r.json() if r.status_code == 200 else None
    except Exception: return None

def fetch_devices():
    try:
        r = requests.get(f"{API_URL}/devices", timeout=5)
        return pd.DataFrame(r.json()) if r.status_code == 200 else pd.DataFrame()
    except Exception: return pd.DataFrame()

def plotly_defaults():
    return dict(
        paper_bgcolor=THEME["plotly_paper"],
        plot_bgcolor=THEME["plotly_bg"],
        font=dict(family="DM Sans", color=THEME["plotly_font"], size=11),
        margin=dict(l=12, r=12, t=28, b=12),
    )


# ── Sidebar ───────────────────────────────────────────────────────────────────
pulse_color = DANGER if IS_DARK else DANGER
text_color  = THEME["t1"]

with st.sidebar:
    st.markdown(f"""
    <style>
    @keyframes sinblink{{
      0%,100%{{opacity:1;box-shadow:0 0 7px {DANGER},0 0 14px rgba(255,71,87,.4)}}
      50%{{opacity:.4;box-shadow:0 0 2px {DANGER}}}
    }}
    </style>
    <div style="padding:20px 16px 14px;border-bottom:1px solid {THEME['border']};">
      <div style="display:flex;align-items:center;gap:9px;margin-bottom:5px;">
        <div style="width:7px;height:7px;border-radius:50%;background:{DANGER};
                    animation:sinblink 2.2s ease-in-out infinite;flex-shrink:0;"></div>
        <span style="font-family:'DM Sans',sans-serif;font-size:18px;font-weight:700;
                     color:{THEME['t1']};letter-spacing:.08em;">SIN</span>
      </div>
      <div style="font-family:'IBM Plex Mono',monospace;font-size:8px;color:{THEME['t3']};
                  letter-spacing:.16em;text-transform:uppercase;padding-left:16px;">
        Shadows In The Network
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Nav
    nav_items = [
        ("overview",  "Dashboard",      "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z"),
        ("analytics", "Analytics",      "M18 20V10M12 20V4M6 20v-6"),
        ("alerts",    "Alerts",         "M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01"),
        ("assets",    "Assets",         "M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"),
        ("reports",   "Reports",        "M22 12h-4l-3 9L9 3l-3 9H2"),
        ("settings",  "Settings",       "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"),
    ]
    st.markdown(f'<div style="padding:10px 0 6px;">', unsafe_allow_html=True)
    for tab_id, label, path in nav_items:
        active = st.session_state.active_tab == tab_id
        bg     = f"rgba(0,170,255,.08)" if active else "transparent"
        border = f"border-right:2px solid {ACCENT};" if active else ""
        clr    = ACCENT if active else THEME["t2"]
        icon_fill = "#00AAFF" if active else ("#A0AABB" if IS_DARK else "#4A5568")
        icon_bg   = (f"background:{ACCENT};" if active else
                     f"background:{'#1E2535' if IS_DARK else '#EEF0F4'};")
        disabled_style = "" if tab_id in ("overview","analytics","alerts") else "opacity:.4;"
        st.markdown(f"""
        <div style="padding:7px 16px;display:flex;align-items:center;gap:10px;
                    background:{bg};{border}margin-bottom:2px;{disabled_style}
                    cursor:{'pointer' if tab_id in ('overview','analytics','alerts') else 'default'};"
             {'onclick="window.parent.postMessage({type:\'streamlit:setComponentValue\',value:\''+tab_id+'\'}, \'*\')"' if tab_id in ('overview','analytics','alerts') else ''}>
          <div style="width:28px;height:28px;border-radius:7px;{icon_bg}
                      display:flex;align-items:center;justify-content:center;flex-shrink:0;">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                 stroke="{'#fff' if active else icon_fill}" stroke-width="2"
                 stroke-linecap="round" stroke-linejoin="round">
              <path d="{path}"/>
            </svg>
          </div>
          <span style="font-family:'DM Sans',sans-serif;font-size:13px;
                       color:{clr};font-weight:{'600' if active else '400'};">{label}</span>
        </div>""", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown('<hr>', unsafe_allow_html=True)

    # Theme toggle
    st.markdown(f"""
    <div style="padding:10px 16px 4px;">
      <span style="font-family:'DM Sans',sans-serif;font-size:9px;font-weight:700;
                   color:{THEME['t3']};text-transform:uppercase;letter-spacing:.14em;">
        Appearance
      </span>
    </div>""", unsafe_allow_html=True)
    theme_label = "☀️  Light Mode" if IS_DARK else "🌙  Dark Mode"
    if st.button(theme_label):
        st.session_state.theme = "light" if IS_DARK else "dark"
        st.rerun()

    st.markdown(f"""
    <div style="padding:10px 16px 4px;margin-top:6px;">
      <span style="font-family:'DM Sans',sans-serif;font-size:9px;font-weight:700;
                   color:{THEME['t3']};text-transform:uppercase;letter-spacing:.14em;">Actions</span>
    </div>""", unsafe_allow_html=True)
    if st.button("⟳  Refresh Data"):
        st.rerun()

    st.markdown(f"""
    <div style="padding:10px 16px 4px;">
      <span style="font-family:'DM Sans',sans-serif;font-size:9px;font-weight:700;
                   color:{THEME['t3']};text-transform:uppercase;letter-spacing:.14em;">Audit Reports</span>
    </div>""", unsafe_allow_html=True)
    if st.button("↓  Generate PDF Report"):
        with st.spinner("Generating…"):
            df_pdf = fetch_devices()
            if not df_pdf.empty:
                path = generate_pdf_report(df_pdf.to_dict("records"))
                with open(path,"rb") as f: pdf_bytes = f.read()
                st.download_button("⬇  Download Audit PDF", pdf_bytes,
                                   "sin_security_audit.pdf","application/pdf")
                st.success("Report ready.")
            else:
                st.error("No device data.")

    # Tab switcher buttons (real Streamlit)
    st.markdown('<hr>', unsafe_allow_html=True)
    st.markdown(f"""
    <div style="padding:10px 16px 4px;">
      <span style="font-family:'DM Sans',sans-serif;font-size:9px;font-weight:700;
                   color:{THEME['t3']};text-transform:uppercase;letter-spacing:.14em;">Navigation</span>
    </div>""", unsafe_allow_html=True)
    if st.button("📊  Overview"):      st.session_state.active_tab = "overview";  st.rerun()
    if st.button("📈  Analytics"):     st.session_state.active_tab = "analytics"; st.rerun()
    if st.button("🔔  Alerts"):        st.session_state.active_tab = "alerts";    st.rerun()

    st.markdown(f"""
    <div style="position:fixed;bottom:0;width:218px;padding:12px 16px;
                border-top:1px solid {THEME['border']};background:{THEME['sidebar_bg']};">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:6px;">
        <div style="width:6px;height:6px;border-radius:50%;background:{SAFE};box-shadow:0 0 6px {SAFE};"></div>
        <span style="font-family:'DM Sans',sans-serif;font-size:11px;color:{SAFE};font-weight:500;">System Online</span>
      </div>
      <div style="font-family:'IBM Plex Mono',monospace;font-size:9px;color:{THEME['t3']};word-break:break-all;">{API_URL}</div>
    </div>
    """, unsafe_allow_html=True)


# ── Data fetch ────────────────────────────────────────────────────────────────
stats      = fetch_stats()
df         = fetch_devices()
now_ts     = time.strftime("%H:%M:%S")
session_id = time.strftime("%Y%m%d-%H%M%S")

# Derived counts
total = 0; vuln_count = 0; crit_count = 0; clean_count = 0
all_vulns = []
if stats:
    total = stats.get("total_assets_tracked", 0)
if not df.empty:
    total = total or len(df)
    for _, row in df.iterrows():
        vulns = row.get("vulnerabilities", [])
        if not isinstance(vulns, list): vulns = []
        if vulns:
            vuln_count += 1
            for v in vulns:
                v_copy = dict(v)
                v_copy["ip"] = row.get("ip_address","")
                v_copy["hostname"] = row.get("hostname","")
                v_copy["manufacturer"] = row.get("manufacturer","")
                all_vulns.append(v_copy)
            if any(v.get("severity","").upper()=="CRITICAL" for v in vulns):
                crit_count += 1
        else:
            clean_count += 1
all_vulns.sort(key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x.get("severity",""),9))

# ── Page header ───────────────────────────────────────────────────────────────
tab_labels = {"overview":"Security Overview","analytics":"Network Analytics","alerts":"Security Alerts"}
st.markdown(f"""
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
  <div>
    <h1 style="font-family:'DM Sans',sans-serif;font-size:24px;font-weight:700;
               color:{THEME['t1']};margin:0 0 4px;letter-spacing:-.02em;">
      {tab_labels.get(st.session_state.active_tab,'Security Overview')}
    </h1>
    <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:{THEME['t3']};letter-spacing:.05em;">
      SESSION&nbsp;·&nbsp;{session_id}&nbsp;·&nbsp;{now_ts}
    </div>
  </div>
  <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;
              color:{THEME['t3']};background:{THEME['bg2']};
              border:1px solid {THEME['border']};padding:6px 12px;border-radius:6px;">
    {'🌙 DARK' if IS_DARK else '☀️ LIGHT'} THEME
  </div>
</div>
""", unsafe_allow_html=True)

# ── Metric cards (always shown) ───────────────────────────────────────────────
def card(label, value, val_color=None, border=None, icon=None):
    vc = val_color or THEME["t1"]
    bc = border or THEME["border"]
    return f"""
    <div style="background:{THEME['card_bg']};border:1px solid {bc};border-radius:10px;
                padding:18px 20px;position:relative;overflow:hidden;">
      <div style="font-family:'DM Sans',sans-serif;font-size:10px;font-weight:700;
                  text-transform:uppercase;letter-spacing:.12em;color:{THEME['t3']};margin-bottom:8px;">
        {label}
      </div>
      <div style="font-family:'DM Sans',sans-serif;font-size:34px;font-weight:700;
                  color:{vc};line-height:1;">{value}</div>
    </div>"""

if not df.empty or stats:
    c1,c2,c3,c4 = st.columns(4)
    with c1: st.markdown(card("Total Assets",total), unsafe_allow_html=True)
    with c2: st.markdown(card("Vulnerable",vuln_count,DANGER,"rgba(255,71,87,.2)"), unsafe_allow_html=True)
    with c3: st.markdown(card("Critical",crit_count,DANGER,"rgba(255,71,87,.2)"), unsafe_allow_html=True)
    with c4: st.markdown(card("Clean",clean_count,SAFE,"rgba(46,213,115,.18)"), unsafe_allow_html=True)
else:
    st.markdown(f"""
    <div style="background:rgba(255,71,87,.07);border:1px solid rgba(255,71,87,.25);
                border-radius:8px;padding:13px 18px;color:{DANGER};font-size:13px;">
      ⚠ API Offline — run:
      <code style="background:rgba(255,71,87,.12);padding:2px 7px;border-radius:3px;
                   font-family:'IBM Plex Mono',monospace;font-size:11px;">
        uvicorn sin.api.server:app
      </code>
    </div>""", unsafe_allow_html=True)

st.markdown('<div style="height:16px;"></div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# ── TAB: OVERVIEW ─────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
if st.session_state.active_tab == "overview":
    if not df.empty:
        records = df.fillna("").to_dict("records")
        for d in records:
            for k in ("open_ports","vulnerabilities","os_cpe","protocol_hints"):
                if not isinstance(d.get(k), list): d[k] = []
            if not isinstance(d.get("services"),dict): d["services"] = {}
            if not isinstance(d.get("service_versions"),dict): d["service_versions"] = {}

        devs_js    = json.dumps(records)
        vendors_js = json.dumps(sorted({d.get("manufacturer") or "Unknown" for d in records}))

        bg       = THEME['bg']
        bg2      = THEME['bg2']
        bg3      = THEME['bg3']
        t1       = THEME['t1']
        t2       = THEME['t2']
        t3       = THEME['t3']
        border   = THEME['border']

        TABLE_HTML = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&display=swap');
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:{bg};font-family:'DM Sans',sans-serif;color:{t1};
      padding:2px 1px 16px;-webkit-font-smoothing:antialiased;}}
.fbar{{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;}}
.fbar input,.fbar select{{
  background:{bg2};border:1px solid {border};color:{t1};
  font-family:'DM Sans',sans-serif;font-size:12px;padding:8px 12px;
  border-radius:7px;outline:none;transition:border-color .15s,background .15s;}}
.fbar input{{flex:1;min-width:220px;}}
.fbar input::placeholder{{color:{t3};}}
.fbar input:focus,.fbar select:focus{{border-color:rgba(0,170,255,.4);background:{bg3};color:{t1};}}
.fbar select{{color:{t2};cursor:pointer;min-width:120px;}}
.slbl{{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.14em;color:{t3};margin-bottom:10px;}}
.tbl{{width:100%;border-collapse:collapse;background:{bg2};
      border:1px solid {border};border-radius:10px;overflow:hidden;}}
.tbl thead tr{{border-bottom:1px solid {border};}}
.tbl th{{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.13em;
         color:{t3};padding:12px 14px;text-align:left;cursor:pointer;
         user-select:none;white-space:nowrap;transition:color .15s;}}
.tbl th:hover{{color:{t2};}}
.tbl th.sorted{{color:#00AAFF;}}
.si{{margin-left:3px;opacity:.35;}}
.sorted .si{{opacity:1;}}
.tbl tr.dr{{border-bottom:1px solid {'rgba(255,255,255,.04)' if IS_DARK else 'rgba(0,0,0,.04)'};
            cursor:pointer;transition:background .1s;
            opacity:0;animation:rowIn .24s ease forwards;}}
.tbl tr.dr:hover{{background:{bg3};}}
.tbl tr.dr.xopen{{background:{bg3};border-bottom:none;}}
.tbl td{{padding:11px 14px;vertical-align:middle;font-size:12.5px;color:{t1};}}
.ip{{font-family:'IBM Plex Mono',monospace;font-size:12px;color:#4FC3F7;font-weight:500;}}
.mac{{font-family:'IBM Plex Mono',monospace;font-size:10.5px;color:{t2};}}
.osfam{{color:{t2};font-size:11.5px;}}
.ports{{display:flex;flex-wrap:wrap;gap:3px;}}
.pb{{font-family:'IBM Plex Mono',monospace;font-size:9.5px;
     background:rgba(0,170,255,.1);border:1px solid rgba(0,170,255,.22);
     color:#4FC3F7;padding:2px 6px;border-radius:4px;}}
.dib{{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0;}}
.di-cam{{background:linear-gradient(135deg,#0066CC,#00AAFF);}}
.di-nvr{{background:linear-gradient(135deg,#6A0DAD,#9B59B6);}}
.di-rtr{{background:linear-gradient(135deg,#CC5500,#FF8C00);}}
.di-ws {{background:linear-gradient(135deg,#1E8449,#2ED573);}}
.di-srv{{background:linear-gradient(135deg,#1A5276,#2E86C1);}}
.di-iot{{background:linear-gradient(135deg,#7D6608,#F0B90B);}}
.di-prt{{background:linear-gradient(135deg,#633974,#AF7AC5);}}
.di-unk{{background:linear-gradient(135deg,#2C3E50,#4A5568);}}
.dcell{{display:flex;align-items:center;gap:9px;}}
.dlbl{{font-size:12px;color:{t2};max-width:110px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}}
.badge{{display:inline-flex;align-items:center;padding:3px 9px;border-radius:5px;
        font-size:9.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;}}
.bc{{background:rgba(255,71,87,.15);color:#FF4757;border:1px solid rgba(255,71,87,.3);}}
.bh{{background:rgba(255,165,2,.14);color:#FFA502;border:1px solid rgba(255,165,2,.28);}}
.bm{{background:rgba(0,170,255,.14);color:#00AAFF;border:1px solid rgba(0,170,255,.28);}}
.bl{{background:rgba(46,213,115,.12);color:#2ED573;border:1px solid rgba(46,213,115,.25);}}
.bk{{background:rgba(46,213,115,.1);color:#2ED573;border:1px solid rgba(46,213,115,.2);}}
.expind{{width:18px;height:18px;border-radius:4px;background:{'rgba(255,255,255,.06)' if IS_DARK else 'rgba(0,0,0,.06)'};
         display:flex;align-items:center;justify-content:center;
         transition:transform .2s ease,background .15s;flex-shrink:0;}}
.dr.xopen .expind{{transform:rotate(90deg);background:rgba(0,170,255,.15);}}
tr.xr td{{padding:0;}}
.xpanel{{display:none;overflow:hidden;max-height:0;opacity:0;
         transition:max-height .22s ease,opacity .18s ease;
         background:{'#0F1318' if IS_DARK else '#F7F9FC'};
         border-top:1px solid rgba(0,170,255,.18);border-bottom:1px solid {border};}}
.xpanel.open{{display:flex;max-height:700px;opacity:1;padding:18px 20px;gap:24px;flex-wrap:wrap;}}
.xf{{flex:1;min-width:240px;}} .xv{{flex:1.4;min-width:280px;}}
.xdt{{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.14em;
      color:{t3};margin-bottom:12px;padding-bottom:6px;
      border-bottom:1px solid {'rgba(255,255,255,.05)' if IS_DARK else 'rgba(0,0,0,.06)'};}}
.kv{{display:flex;margin-bottom:6px;align-items:flex-start;font-size:11.5px;}}
.kk{{color:{t3};min-width:130px;flex-shrink:0;padding-right:8px;}}
.kv2{{font-family:'IBM Plex Mono',monospace;font-size:10.5px;color:{t1};word-break:break-all;line-height:1.5;}}
.kv2.dim{{color:{t2};font-family:'DM Sans',sans-serif;font-size:11.5px;}}
.vi{{margin-bottom:8px;padding:10px 12px;background:{bg2};border-radius:6px;border-left:3px solid;}}
.vi-c{{border-color:#FF4757;}} .vi-h{{border-color:#FFA502;}}
.vi-m{{border-color:#00AAFF;}} .vi-l{{border-color:#2ED573;}}
.vhdr{{display:flex;align-items:center;gap:7px;margin-bottom:5px;flex-wrap:wrap;}}
.vcve{{font-family:'IBM Plex Mono',monospace;font-size:9.5px;color:{t3};
       background:{'rgba(255,255,255,.04)' if IS_DARK else 'rgba(0,0,0,.04)'};padding:2px 6px;border-radius:3px;}}
.vdesc{{font-size:11px;color:{t2};line-height:1.6;}}
.no-v{{display:flex;align-items:center;gap:7px;color:#2ED573;font-size:12px;}}
.smbadge{{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;
          padding:2px 7px;border-radius:4px;display:inline-block;}}
.sm-nmap{{background:rgba(46,213,115,.1);border:1px solid rgba(46,213,115,.25);color:#2ED573;}}
.sm-native{{background:{'rgba(160,170,187,.08)' if IS_DARK else 'rgba(0,0,0,.06)'};
            border:1px solid {'rgba(160,170,187,.15)' if IS_DARK else 'rgba(0,0,0,.1)'};color:{t2};}}
.empty{{text-align:center;padding:52px;color:{t3};font-size:13px;}}
@keyframes rowIn{{from{{opacity:0;transform:translateY(4px)}}to{{opacity:1;transform:translateY(0)}}}}
</style></head><body>
<div class="fbar">
  <input id="srch" type="text" placeholder="Search IP, hostname, MAC, vendor, OS…" oninput="go()">
  <select id="sevF" onchange="go()">
    <option value="">All Severity</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="CLEAN">Clean</option>
  </select>
  <select id="typeF" onchange="go()">
    <option value="">All Types</option>
    <option value="camera">Camera</option>
    <option value="nvr_dvr">NVR / DVR</option>
    <option value="router">Router</option>
    <option value="workstation">Workstation</option>
    <option value="server">Server</option>
    <option value="iot">IoT</option>
    <option value="unknown">Unknown</option>
  </select>
  <select id="venF" onchange="go()"></select>
</div>
<div class="slbl" id="countLbl">Live Asset Inventory</div>
<table class="tbl">
<thead><tr>
  <th style="width:40px;padding-left:12px;"></th>
  <th onclick="srt('ip_address')">IP Address<span class="si">&#8597;</span></th>
  <th onclick="srt('mac_address')">MAC Address<span class="si">&#8597;</span></th>
  <th onclick="srt('hostname')">Hostname<span class="si">&#8597;</span></th>
  <th onclick="srt('manufacturer')">Device / Vendor<span class="si">&#8597;</span></th>
  <th onclick="srt('os_family')">OS / Type<span class="si">&#8597;</span></th>
  <th>Open Ports</th>
  <th onclick="srt('_risk')">Risk<span class="si">&#8597;</span></th>
</tr></thead>
<tbody id="tbody"></tbody>
</table>
<script>
const DEVS={devs_js};
const VENS={vendors_js};
const vf=document.getElementById('venF');
[['','All Vendors'],...VENS.map(v=>[v,v])].forEach(([val,txt])=>{{
  const o=document.createElement('option');o.value=val;o.textContent=txt;vf.appendChild(o);
}});
let CS={{k:null,asc:true}};
const ORD={{'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'CLEAN':4}};
function topSev(v){{
  if(!v||!v.length)return'CLEAN';
  for(const s of['CRITICAL','HIGH','MEDIUM','LOW'])
    if(v.some(x=>(x.severity||'').toUpperCase()===s))return s;
  return'LOW';
}}
function badge(s){{
  const m={{'CRITICAL':'bc','HIGH':'bh','MEDIUM':'bm','LOW':'bl','CLEAN':'bk'}};
  return'<span class="badge '+(m[s]||'bk')+'">'+s+'</span>';
}}
const ICONS={{
  camera:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="13" rx="2"/><circle cx="12" cy="13" r="3"/><path d="M16 7l-1.5-3h-5L8 7"/></svg>',
  nvr_dvr:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
  router:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round"><rect x="1" y="8" width="22" height="8" rx="2"/><circle cx="6" cy="12" r="1" fill="#fff"/><circle cx="10" cy="12" r="1" fill="#fff"/><circle cx="14" cy="12" r="1" fill="#fff"/><line x1="6" y1="8" x2="4" y2="5"/><line x1="12" y1="8" x2="12" y2="5"/><line x1="18" y1="8" x2="20" y2="5"/></svg>',
  workstation:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',
  server:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="18" cy="6" r="1" fill="#fff"/><circle cx="18" cy="18" r="1" fill="#fff"/></svg>',
  iot:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round"><path d="M12 2a10 10 0 1 0 10 10"/><path d="M12 6a6 6 0 0 1 6 6"/><circle cx="12" cy="12" r="2" fill="#fff" stroke="none"/></svg>',
  printer:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>',
  unknown:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
}};
const ICLS={{camera:'di-cam',nvr_dvr:'di-nvr',router:'di-rtr',workstation:'di-ws',server:'di-srv',iot:'di-iot',printer:'di-prt',unknown:'di-unk'}};
function typeIcon(t){{return'<div class="dib '+(ICLS[t]||'di-unk')+'">'+(ICONS[t]||ICONS.unknown)+'</div>';}}
function portBadges(arr){{
  if(!arr||!arr.length)return'<span style="color:{t3};font-size:10px;">&#8212;</span>';
  let h=arr.slice(0,5).map(p=>'<span class="pb">'+p+'</span>').join('');
  if(arr.length>5)h+='<span class="pb" style="opacity:.45;">+'+(arr.length-5)+'</span>';
  return'<div class="ports">'+h+'</div>';
}}
function detailPanel(d){{
  const sm=d.scan_method||'native';
  const rows=[
    ['IP Address','<span class="kv2">'+(d.ip_address||'&#8212;')+'</span>'],
    ['MAC Address','<span class="kv2">'+(d.mac_address||'&#8212;')+'</span>'],
    ['Hostname','<span class="kv2 dim">'+(d.hostname||'&#8212;')+'</span>'],
    ['Manufacturer','<span class="kv2 dim">'+(d.manufacturer||'&#8212;')+'</span>'],
    ['OS Family','<span class="kv2 dim">'+(d.os_family||'&#8212;')+'</span>'],
  ];
  if(d.os_details)rows.push(['OS Detail','<span class="kv2 dim">'+d.os_details+'</span>']);
  if(d.os_accuracy>0)rows.push(['OS Accuracy','<span class="kv2 dim">'+d.os_accuracy+'%</span>']);
  if(d.device_type)rows.push(['Device Type','<span class="kv2 dim" style="text-transform:capitalize;">'+d.device_type.replace('_',' ')+'</span>']);
  rows.push(['TTL','<span class="kv2">'+(d.ttl||'&#8212;')+'</span>']);
  if(d.last_seen)rows.push(['Last Seen','<span class="kv2 dim">'+d.last_seen.replace('T',' ').slice(0,19)+'Z</span>']);
  rows.push(['Scan Method','<span class="smbadge sm-'+sm+'">'+sm+'</span>']);
  const sv=d.service_versions,svc=d.services;
  if(sv&&Object.keys(sv).length){{
    const lines=Object.entries(sv).map(([p,s])=>'<span class="kv2 dim">'+p+' / '+(s.product||s.name||'?')+(s.version?' '+s.version:'')+'</span>');
    rows.push(['Services','<div style="display:flex;flex-direction:column;gap:3px;">'+lines.join('')+'</div>']);
  }}else if(svc&&Object.keys(svc).length){{
    const lines=Object.entries(svc).map(([p,s])=>'<span class="kv2 dim">'+p+' / '+s+'</span>');
    rows.push(['Services','<div style="display:flex;flex-direction:column;gap:3px;">'+lines.join('')+'</div>']);
  }}
  if(d.os_cpe&&d.os_cpe.length)rows.push(['CPE','<span class="kv2" style="font-size:9.5px;opacity:.65;">'+d.os_cpe.slice(0,2).join('<br>')+'</span>']);
  const fhtml=rows.map(([k,v])=>'<div class="kv"><span class="kk">'+k+'</span>'+v+'</div>').join('');
  let vhtml='';
  if(!d.vulnerabilities||!d.vulnerabilities.length){{
    vhtml='<div class="no-v"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2ED573" stroke-width="2.5" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>No vulnerabilities detected</div>';
  }}else{{
    vhtml=d.vulnerabilities.map(v=>{{
      const sl=(v.severity||'low').toLowerCase()[0];
      return'<div class="vi vi-'+sl+'"><div class="vhdr">'+badge((v.severity||'LOW').toUpperCase())+(v.cve?'<span class="vcve">'+v.cve+'</span>':'')+'<span style="font-size:10.5px;color:{t2};">'+( v.type||'')+'</span></div><div class="vdesc">'+(v.description||'')+'</div></div>';
    }}).join('');
  }}
  return'<div class="xpanel open"><div class="xf"><div class="xdt">Asset Details</div>'+fhtml+'</div><div class="xv"><div class="xdt">Vulnerabilities ('+((d.vulnerabilities||[]).length)+')</div>'+vhtml+'</div></div>';
}}
function render(devs){{
  const tb=document.getElementById('tbody');
  tb.innerHTML='';
  document.getElementById('countLbl').textContent='Live Asset Inventory \u2014 '+devs.length+' device'+(devs.length!==1?'s':'');
  if(!devs.length){{tb.innerHTML='<tr><td colspan="8"><div class="empty">No devices match filters.</div></td></tr>';return;}}
  devs.forEach((d,i)=>{{
    const sev=topSev(d.vulnerabilities);const dt=d.device_type||'unknown';
    const tr=document.createElement('tr');tr.className='dr';tr.style.animationDelay=(i*25)+'ms';
    tr.innerHTML='<td style="padding-left:12px;"><div class="expind"><svg width="8" height="8" viewBox="0 0 8 8" fill="none"><polyline points="2,1 6,4 2,7" stroke="{t2}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg></div></td>'
      +'<td><span class="ip">'+(d.ip_address||'&#8212;')+'</span></td>'
      +'<td><span class="mac">'+(d.mac_address||'&#8212;')+'</span></td>'
      +'<td style="color:{t1};">'+(d.hostname||'&#8212;')+'</td>'
      +'<td><div class="dcell">'+typeIcon(dt)+'<span class="dlbl">'+(d.manufacturer||'Unknown')+'</span></div></td>'
      +'<td><span class="osfam">'+(d.os_family||'&#8212;')+'</span></td>'
      +'<td>'+portBadges(d.open_ports)+'</td>'
      +'<td>'+badge(sev)+'</td>';
    const xtr=document.createElement('tr');xtr.className='xr';
    const xtd=document.createElement('td');xtd.colSpan=8;
    xtd.innerHTML=detailPanel(d);
    const panel=xtd.querySelector('.xpanel');panel.classList.remove('open');
    xtr.appendChild(xtd);
    tr.addEventListener('click',()=>{{
      const isOpen=panel.classList.contains('open');
      document.querySelectorAll('.xpanel.open').forEach(p=>p.classList.remove('open'));
      document.querySelectorAll('.dr.xopen').forEach(r=>r.classList.remove('xopen'));
      if(!isOpen){{panel.classList.add('open');tr.classList.add('xopen');}}
    }});
    tb.appendChild(tr);tb.appendChild(xtr);
  }});
}}
function sortArr(arr){{
  if(!CS.k)return arr;
  return[...arr].sort((a,b)=>{{
    let va,vb;
    if(CS.k==='_risk'){{
      va=ORD[topSev(a.vulnerabilities)]??5;vb=ORD[topSev(b.vulnerabilities)]??5;
      return CS.asc?va-vb:vb-va;
    }}
    va=(a[CS.k]||'').toString().toLowerCase();vb=(b[CS.k]||'').toString().toLowerCase();
    if(va<vb)return CS.asc?-1:1;if(va>vb)return CS.asc?1:-1;return 0;
  }});
}}
function go(){{
  const q=document.getElementById('srch').value.toLowerCase();
  const sv=document.getElementById('sevF').value.toUpperCase();
  const ty=document.getElementById('typeF').value;
  const vn=document.getElementById('venF').value.toLowerCase();
  let f=DEVS.filter(d=>{{
    const ms=!q||(d.ip_address||'').toLowerCase().includes(q)||(d.hostname||'').toLowerCase().includes(q)||(d.mac_address||'').toLowerCase().includes(q)||(d.manufacturer||'').toLowerCase().includes(q)||(d.os_family||'').toLowerCase().includes(q);
    const ts=topSev(d.vulnerabilities);
    return ms&&(!sv||ts===sv)&&(!ty||(d.device_type||'unknown')===ty)&&(!vn||(d.manufacturer||'').toLowerCase().includes(vn));
  }});
  render(sortArr(f));
}}
function srt(k){{
  document.querySelectorAll('.tbl th').forEach(h=>h.classList.remove('sorted'));
  CS.asc=CS.k===k?!CS.asc:true;CS.k=k;
  const cols=['_x','ip_address','mac_address','hostname','manufacturer','os_family','_ports','_risk'];
  const idx=cols.indexOf(k);if(idx>=0)document.querySelectorAll('.tbl th')[idx].classList.add('sorted');
  go();
}}
go();
</script></body></html>"""

        components.html(TABLE_HTML, height=740, scrolling=True)
    else:
        st.markdown(f"""
        <div style="background:{THEME['bg2']};border:1px solid {THEME['border']};
                    border-radius:10px;padding:52px;text-align:center;">
          <div style="font-family:'DM Sans',sans-serif;color:{THEME['t3']};font-size:14px;">
            No devices found. Run a scan agent to populate data.
          </div>
        </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# ── TAB: ANALYTICS ────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.active_tab == "analytics":
    if df.empty:
        st.info("No device data available. Run a scan to populate analytics.")
    else:
        defaults = plotly_defaults()

        # ── Row 1: Vendor pie + OS bar ────────────────────────────────────────
        col_l, col_r = st.columns(2)

        with col_l:
            st.markdown(f"""
            <div style="background:{THEME['card_bg']};border:1px solid {THEME['border']};
                        border-radius:10px;padding:14px 18px 4px;">
              <div style="font-family:'DM Sans',sans-serif;font-size:11px;font-weight:700;
                          text-transform:uppercase;letter-spacing:.12em;color:{THEME['t3']};margin-bottom:8px;">
                Device Vendor Distribution
              </div>""", unsafe_allow_html=True)
            vendor_counts = df["manufacturer"].fillna("Unknown").value_counts().reset_index()
            vendor_counts.columns = ["Vendor","Count"]
            colors = [ACCENT,"#FF4757","#2ED573","#FFA502","#9B59B6","#E74C3C","#3498DB","#27AE60"]
            fig_v = px.pie(vendor_counts, names="Vendor", values="Count",
                           color_discrete_sequence=colors, hole=0.45)
            fig_v.update_traces(textfont_size=11, textfont_family="DM Sans",
                                textinfo="percent+label",
                                hovertemplate="<b>%{label}</b><br>Devices: %{value}<br>Share: %{percent}<extra></extra>")
            fig_v.update_layout(**defaults, height=280,
                                legend=dict(font=dict(size=10,family="DM Sans",color=THEME["plotly_font"]),
                                           bgcolor="rgba(0,0,0,0)",borderwidth=0,orientation="v"))
            st.plotly_chart(fig_v, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)

        with col_r:
            st.markdown(f"""
            <div style="background:{THEME['card_bg']};border:1px solid {THEME['border']};
                        border-radius:10px;padding:14px 18px 4px;">
              <div style="font-family:'DM Sans',sans-serif;font-size:11px;font-weight:700;
                          text-transform:uppercase;letter-spacing:.12em;color:{THEME['t3']};margin-bottom:8px;">
                OS / Device Family
              </div>""", unsafe_allow_html=True)
            os_counts = df["os_family"].fillna("Unknown").value_counts().head(8).reset_index()
            os_counts.columns = ["OS","Count"]
            fig_os = px.bar(os_counts, x="Count", y="OS", orientation="h",
                            color="Count", color_continuous_scale=[[0,THEME['bg3']],[1,ACCENT]])
            fig_os.update_traces(hovertemplate="<b>%{y}</b><br>Devices: %{x}<extra></extra>")
            fig_os.update_layout(**defaults, height=280,
                                 yaxis=dict(categoryorder="total ascending",tickfont=dict(size=10)),
                                 xaxis=dict(showgrid=True,gridcolor=THEME["plotly_grid"]),
                                 coloraxis_showscale=False)
            st.plotly_chart(fig_os, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div style="height:12px;"></div>', unsafe_allow_html=True)

        # ── Row 2: Risk donut + Port frequency ───────────────────────────────
        col_l2, col_r2 = st.columns(2)

        with col_l2:
            st.markdown(f"""
            <div style="background:{THEME['card_bg']};border:1px solid {THEME['border']};
                        border-radius:10px;padding:14px 18px 4px;">
              <div style="font-family:'DM Sans',sans-serif;font-size:11px;font-weight:700;
                          text-transform:uppercase;letter-spacing:.12em;color:{THEME['t3']};margin-bottom:8px;">
                Risk Profile Breakdown
              </div>""", unsafe_allow_html=True)
            sev_map = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
            risk_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"CLEAN":0}
            for _, row in df.iterrows():
                vulns = row.get("vulnerabilities",[])
                if not isinstance(vulns,list): vulns=[]
                top = "CLEAN"
                for s in ["CRITICAL","HIGH","MEDIUM","LOW"]:
                    if any(v.get("severity","").upper()==s for v in vulns):
                        top = s; break
                risk_counts[top] = risk_counts.get(top,0)+1
            risk_df = pd.DataFrame(list(risk_counts.items()),columns=["Risk","Count"])
            risk_df = risk_df[risk_df["Count"]>0]
            risk_colors = {"CRITICAL":DANGER,"HIGH":WARN,"MEDIUM":ACCENT,"LOW":"#2ECC71","CLEAN":SAFE}
            fig_r = px.pie(risk_df, names="Risk", values="Count", hole=0.5,
                           color="Risk", color_discrete_map=risk_colors)
            fig_r.update_traces(textfont_size=11,textfont_family="DM Sans",
                                textinfo="percent+label",
                                hovertemplate="<b>%{label}</b><br>Devices: %{value}<extra></extra>")
            fig_r.update_layout(**defaults, height=280,
                                legend=dict(font=dict(size=10,family="DM Sans",color=THEME["plotly_font"]),
                                           bgcolor="rgba(0,0,0,0)",borderwidth=0))
            st.plotly_chart(fig_r, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)

        with col_r2:
            st.markdown(f"""
            <div style="background:{THEME['card_bg']};border:1px solid {THEME['border']};
                        border-radius:10px;padding:14px 18px 4px;">
              <div style="font-family:'DM Sans',sans-serif;font-size:11px;font-weight:700;
                          text-transform:uppercase;letter-spacing:.12em;color:{THEME['t3']};margin-bottom:8px;">
                Top Open Ports Across Network
              </div>""", unsafe_allow_html=True)
            from collections import Counter
            port_ctr: Counter = Counter()
            port_svc_map = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
                            80:"HTTP",110:"POP3",143:"IMAP",161:"SNMP",443:"HTTPS",
                            445:"SMB",502:"Modbus",554:"RTSP",1883:"MQTT",3306:"MySQL",
                            3389:"RDP",8080:"HTTP-Alt",8443:"HTTPS-Alt",37777:"Dahua-SDK",34567:"DVR-Web"}
            for _, row in df.iterrows():
                ports_raw = row.get("open_ports",[])
                if isinstance(ports_raw,list):
                    port_ctr.update(ports_raw)
            if port_ctr:
                top_ports = port_ctr.most_common(12)
                ports_df = pd.DataFrame(top_ports, columns=["Port","Count"])
                ports_df["Label"] = ports_df["Port"].apply(lambda p: f"{p}/{port_svc_map.get(p,'?')}")
                bar_colors = [DANGER if p in (23,21,37777,34567,1883) else
                              WARN   if p in (3389,161,502,47808) else ACCENT
                              for p in ports_df["Port"]]
                fig_p = px.bar(ports_df, x="Label", y="Count", color_discrete_sequence=[ACCENT])
                fig_p.update_traces(marker_color=bar_colors,
                                    hovertemplate="<b>Port %{x}</b><br>Devices: %{y}<extra></extra>")
                fig_p.update_layout(**defaults, height=280,
                                    xaxis=dict(tickfont=dict(size=9),tickangle=-30),
                                    yaxis=dict(showgrid=True,gridcolor=THEME["plotly_grid"]))
                st.plotly_chart(fig_p, use_container_width=True)
            else:
                st.markdown(f'<div style="color:{THEME["t3"]};padding:40px;text-align:center;font-size:13px;">No open ports detected.</div>', unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div style="height:12px;"></div>', unsafe_allow_html=True)

        # ── Row 3: Device type bar + Vulnerability type breakdown ────────────
        col_l3, col_r3 = st.columns(2)

        with col_l3:
            st.markdown(f"""
            <div style="background:{THEME['card_bg']};border:1px solid {THEME['border']};
                        border-radius:10px;padding:14px 18px 4px;">
              <div style="font-family:'DM Sans',sans-serif;font-size:11px;font-weight:700;
                          text-transform:uppercase;letter-spacing:.12em;color:{THEME['t3']};margin-bottom:8px;">
                Device Type Classification
              </div>""", unsafe_allow_html=True)
            if "device_type" in df.columns:
                dt_counts = df["device_type"].fillna("unknown").value_counts().reset_index()
                dt_counts.columns = ["Type","Count"]
                dt_counts["Type"] = dt_counts["Type"].str.replace("_"," ").str.title()
                dt_colors = ["#00AAFF","#9B59B6","#FF8C00","#2ED573","#2E86C1","#F0B90B","#AF7AC5","#4A5568"]
                fig_dt = px.bar(dt_counts, x="Type", y="Count",
                                color="Type", color_discrete_sequence=dt_colors)
                fig_dt.update_traces(hovertemplate="<b>%{x}</b><br>Count: %{y}<extra></extra>")
                fig_dt.update_layout(**defaults, height=270, showlegend=False,
                                     xaxis=dict(tickfont=dict(size=10)),
                                     yaxis=dict(showgrid=True,gridcolor=THEME["plotly_grid"]))
                st.plotly_chart(fig_dt, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)

        with col_r3:
            st.markdown(f"""
            <div style="background:{THEME['card_bg']};border:1px solid {THEME['border']};
                        border-radius:10px;padding:14px 18px 4px;">
              <div style="font-family:'DM Sans',sans-serif;font-size:11px;font-weight:700;
                          text-transform:uppercase;letter-spacing:.12em;color:{THEME['t3']};margin-bottom:8px;">
                Vulnerability Type Breakdown
              </div>""", unsafe_allow_html=True)
            if all_vulns:
                vtype_ctr: Counter = Counter()
                for v in all_vulns: vtype_ctr[v.get("type","Unknown")] += 1
                vt_df = pd.DataFrame(list(vtype_ctr.most_common(10)), columns=["Type","Count"])
                fig_vt = px.bar(vt_df, x="Count", y="Type", orientation="h",
                                color="Count",
                                color_continuous_scale=[[0,THEME['bg3']],[0.5,WARN],[1,DANGER]])
                fig_vt.update_traces(hovertemplate="<b>%{y}</b><br>Occurrences: %{x}<extra></extra>")
                fig_vt.update_layout(**defaults, height=270, coloraxis_showscale=False,
                                     yaxis=dict(categoryorder="total ascending",tickfont=dict(size=9)),
                                     xaxis=dict(showgrid=True,gridcolor=THEME["plotly_grid"]))
                st.plotly_chart(fig_vt, use_container_width=True)
            else:
                st.markdown(f'<div style="color:{THEME["t3"]};padding:40px;text-align:center;font-size:13px;">No vulnerabilities to chart.</div>', unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# ── TAB: ALERTS ───────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.active_tab == "alerts":
    if not all_vulns:
        st.markdown(f"""
        <div style="background:{THEME['card_bg']};border:1px solid rgba(46,213,115,.2);
                    border-radius:10px;padding:40px;text-align:center;">
          <div style="font-size:32px;margin-bottom:12px;">✅</div>
          <div style="font-family:'DM Sans',sans-serif;color:{SAFE};font-size:15px;font-weight:600;">
            No Active Alerts
          </div>
          <div style="font-family:'DM Sans',sans-serif;color:{THEME['t3']};font-size:13px;margin-top:6px;">
            All scanned devices are clean.
          </div>
        </div>""", unsafe_allow_html=True)
    else:
        # Summary strip
        sev_counts = Counter(v.get("severity","?") for v in all_vulns)
        s1,s2,s3,s4 = st.columns(4)
        def alert_mini(label, count, color):
            return f"""
            <div style="background:{THEME['card_bg']};border:1px solid {color}33;border-radius:8px;padding:14px 16px;">
              <div style="font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.12em;color:{THEME['t3']};margin-bottom:6px;">{label}</div>
              <div style="font-size:28px;font-weight:700;color:{color};">{count}</div>
            </div>"""
        with s1: st.markdown(alert_mini("Critical",sev_counts.get("CRITICAL",0),DANGER), unsafe_allow_html=True)
        with s2: st.markdown(alert_mini("High",sev_counts.get("HIGH",0),WARN), unsafe_allow_html=True)
        with s3: st.markdown(alert_mini("Medium",sev_counts.get("MEDIUM",0),ACCENT), unsafe_allow_html=True)
        with s4: st.markdown(alert_mini("Low",sev_counts.get("LOW",0),SAFE), unsafe_allow_html=True)

        st.markdown('<div style="height:16px;"></div>', unsafe_allow_html=True)

        # Filter
        sev_filter = st.selectbox("Filter by severity", ["All","CRITICAL","HIGH","MEDIUM","LOW"],
                                  label_visibility="collapsed")
        filtered_vulns = all_vulns if sev_filter=="All" else [v for v in all_vulns if v.get("severity")==sev_filter]

        st.markdown(f"""
        <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.14em;
                    color:{THEME['t3']};margin:10px 0 8px;">
          {len(filtered_vulns)} Alert{'s' if len(filtered_vulns)!=1 else ''}
        </div>""", unsafe_allow_html=True)

        sev_clr = {"CRITICAL":DANGER,"HIGH":WARN,"MEDIUM":ACCENT,"LOW":SAFE}
        sev_border = {"CRITICAL":"rgba(255,71,87,.3)","HIGH":"rgba(255,165,2,.28)",
                      "MEDIUM":"rgba(0,170,255,.28)","LOW":"rgba(46,213,115,.25)"}

        for v in filtered_vulns:
            sev  = v.get("severity","LOW")
            clr  = sev_clr.get(sev, SAFE)
            brd  = sev_border.get(sev, THEME["border"])
            ip   = v.get("ip","")
            host = v.get("hostname","")
            mfr  = v.get("manufacturer","")
            host_str = f"{host} ({ip})" if host and host != "Unknown" and host != ip else ip

            st.markdown(f"""
            <div style="background:{THEME['card_bg']};border:1px solid {brd};
                        border-left:3px solid {clr};border-radius:8px;
                        padding:14px 16px;margin-bottom:8px;">
              <div style="display:flex;align-items:flex-start;justify-content:space-between;
                          flex-wrap:wrap;gap:8px;margin-bottom:8px;">
                <div style="display:flex;align-items:center;gap:8px;">
                  <span style="background:{clr}22;color:{clr};border:1px solid {clr}44;
                               padding:2px 8px;border-radius:4px;font-size:9.5px;
                               font-weight:700;letter-spacing:.07em;">{sev}</span>
                  <span style="font-family:'DM Sans',sans-serif;font-size:13px;
                               font-weight:600;color:{THEME['t1']};">{v.get('type','')}</span>
                </div>
                <div style="display:flex;align-items:center;gap:8px;">
                  <span style="font-family:'IBM Plex Mono',monospace;font-size:10.5px;
                               color:{ACCENT};">{host_str}</span>
                  {f'<span style="font-size:10.5px;color:{THEME["t3"]};">{mfr}</span>' if mfr and mfr!="Unknown" else ""}
                </div>
              </div>
              <div style="font-size:12px;color:{THEME['t2']};line-height:1.6;margin-bottom:6px;">
                {v.get('description','')}
              </div>
              {f'<span style="font-family:IBM Plex Mono,monospace;font-size:9.5px;color:{THEME["t3"]};background:{THEME["bg3"]};padding:2px 7px;border-radius:3px;">{v.get("cve","")}</span>' if v.get("cve") else ""}
            </div>""", unsafe_allow_html=True)

# ── Auto-refresh every 30s ────────────────────────────────────────────────────
time.sleep(30)
st.rerun()
