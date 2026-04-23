import streamlit as st
import pandas as pd
import requests
import plotly.express as px
from sqlalchemy import create_engine
import ast

# --- 1. Enterprise Configuration ---
st.set_page_config(page_title="SIN Enterprise | Command Center", layout="wide", page_icon="🛡️")

# --- 2. Data Ingestion & Caching ---
DB_URL = "postgresql://sin_user:secure_dev_password@db:5432/sin_network_db"

@st.cache_data(ttl=3)  # Ultra-fast 3-second refresh for live feel
def load_live_telemetry():
    try:
        engine = create_engine(DB_URL)
        devices_df = pd.read_sql_table('device_logs', engine)
        events_df = pd.read_sql_table('security_events', engine)
        
        # Clean and categorize data
        if not devices_df.empty:
            # Drop dead IPs strictly
            devices_df = devices_df[devices_df['status'].str.lower() == 'online']
            
            # Prioritization Logic for CCTV/IoT
            cctv_keywords = ['camera', 'nvr', 'dvr', 'iot', 'embedded', 'video', 'surveillance']
            devices_df['is_cctv'] = devices_df['device_type'].astype(str).str.lower().apply(
                lambda x: any(kw in x for k in cctv_keywords for kw in cctv_keywords)
            )
            
            # Parse vulnerabilities cleanly
            devices_df['vuln_count'] = devices_df['vulnerabilities'].apply(
                lambda x: len(ast.literal_eval(x)) if isinstance(x, str) and x != '[]' else (len(x) if isinstance(x, list) else 0)
            )
            
            # Sort: CCTV/IoT at the top, then by vulnerability count
            devices_df = devices_df.sort_values(by=['is_cctv', 'vuln_count'], ascending=[False, False])
            
        return devices_df, events_df
    except Exception as e:
        return pd.DataFrame(), pd.DataFrame()

df, events_df = load_live_telemetry()

# --- 3. Global Sidebar & Control Plane ---
st.sidebar.title("🛡️ SIN Enterprise")
st.sidebar.markdown("---")

# Navigation Routing
page = st.sidebar.radio("Navigation", ["📊 Dashboard", "🎯 Live Asset Registry", "📑 Threat Reports", "⚙️ Settings"])
st.sidebar.markdown("---")

st.sidebar.subheader("📡 Active Scanner")
target_subnet = st.sidebar.text_input("Target Network", value="192.168.30")

if st.sidebar.button("🚀 Launch Tactical Scan", use_container_width=True):
    with st.sidebar.status("Dispatching to Engine...", expanded=True) as status:
        try:
            res = requests.post("http://api:8000/scan/trigger", json={"subnet": target_subnet}, timeout=5)
            if res.status_code == 200:
                status.update(label="Scan Active!", state="complete")
                st.sidebar.success("Engine deployed. Registry will auto-update.")
            else:
                status.update(label="API Error", state="error")
        except:
            status.update(label="API Offline", state="error")
            st.sidebar.error("Cannot reach scanning API.")

# --- 4. View Routing ---

if page == "📊 Dashboard":
    st.title("Command Center Overview")
    if df.empty:
        st.info("Awaiting telemetry. Launch a scan from the sidebar.")
    else:
        # High-level Metrics
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Live Network Nodes", len(df))
        c2.metric("IoT / CCTV Devices", len(df[df['is_cctv'] == True]), delta="Priority Target", delta_color="off")
        c3.metric("Vulnerable Assets", len(df[df['vuln_count'] > 0]), delta_color="inverse")
        c4.metric("Critical Security Events", len(events_df[events_df['severity'] == 'CRITICAL']) if not events_df.empty else 0, delta_color="inverse")
        
        st.markdown("---")
        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            fig1 = px.pie(df, names='vendor', title='Hardware Distribution', hole=0.4, template="plotly_dark")
            st.plotly_chart(fig1, use_container_width=True)
        with chart_col2:
            fig2 = px.bar(df, x='device_type', title='Asset Classification', color='is_cctv', template="plotly_dark", color_discrete_map={True: '#d62728', False: '#1f77b4'})
            st.plotly_chart(fig2, use_container_width=True)

elif page == "🎯 Live Asset Registry":
    st.title("Live Asset Registry")
    
    if df.empty:
        st.warning("No active assets detected.")
    else:
        # Dynamic Search & Filters
        f1, f2, f3 = st.columns([2, 1, 1])
        search_query = f1.text_input("🔍 Global Search (IP, MAC, Vendor, OS)...", "")
        filter_type = f2.selectbox("Filter Category", ["All Assets", "CCTV & IoT Only", "Standard IT"])
        filter_vuln = f3.selectbox("Threat Status", ["All", "Vulnerable Only"])

        # Apply Live Filters
        filtered_df = df.copy()
        if search_query:
            mask = filtered_df.astype(str).apply(lambda x: x.str.contains(search_query, case=False)).any(axis=1)
            filtered_df = filtered_df[mask]
        
        if filter_type == "CCTV & IoT Only":
            filtered_df = filtered_df[filtered_df['is_cctv'] == True]
        elif filter_type == "Standard IT":
            filtered_df = filtered_df[filtered_df['is_cctv'] == False]
            
        if filter_vuln == "Vulnerable Only":
            filtered_df = filtered_df[filtered_df['vuln_count'] > 0]

        st.caption(f"Displaying {len(filtered_df)} live targets.")
        
        # Render Interactive Detail List
        for _, row in filtered_df.iterrows():
            # Highlight CCTV / Vulnerable devices
            icon = "📷" if row['is_cctv'] else "💻"
            alert = "🔴" if row['vuln_count'] > 0 else "🟢"
            
            with st.expander(f"{alert} {icon} {row['ip_address']} | {row['vendor']} {row['device_type']}"):
                col_a, col_b, col_c = st.columns(3)
                col_a.markdown(f"**MAC Address:** `{row['mac_address']}`")
                col_a.markdown(f"**OS Family:** {row['os_family']}")
                
                col_b.markdown(f"**Status:** {row['status'].upper()}")
                col_b.markdown(f"**Threats Detected:** `{row['vuln_count']}`")
                
                col_c.markdown("**Open Ports:**")
                ports = ast.literal_eval(row['open_ports']) if isinstance(row['open_ports'], str) else row['open_ports']
                col_c.code(", ".join(map(str, ports)) if ports else "None Detected")
                
                if row['vuln_count'] > 0:
                    st.error("**Security Findings:**")
                    try:
                        vulns = ast.literal_eval(row['vulnerabilities'])
                        for v in vulns:
                            st.markdown(f"- **{v.get('severity', 'UNKNOWN')}**: {v.get('type', 'Flaw')} - {v.get('description', '')}")
                    except:
                        st.markdown(f"`{row['vulnerabilities']}`")

elif page == "📑 Threat Reports":
    st.title("Threat Intelligence Reports")
    st.markdown("Automated compliance and exposure summaries.")
    if not events_df.empty:
        st.dataframe(events_df[['timestamp', 'ip_address', 'severity', 'event_type', 'description']].sort_values('timestamp', ascending=False), use_container_width=True)
    else:
        st.success("No critical security events logged.")

elif page == "⚙️ Settings":
    st.title("Engine Configuration")
    st.markdown("Adjust backend scanner behavior and API limits.")
    st.toggle("Aggressive Fingerprinting (Nmap -A)", value=True)
    st.toggle("Enable DeepSeek Cognitive AI Engine", value=True)
    st.slider("Concurrent Worker Threads", 1, 50, 10)
    st.button("Save Configuration", type="primary")
