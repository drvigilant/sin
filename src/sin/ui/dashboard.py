import streamlit as st
import pandas as pd
import requests
import plotly.express as px
import time
import os
# NEW IMPORT
from sin.response.report import generate_pdf_report

# Configuration
API_URL = os.getenv("SIN_API_URL", "http://localhost:8000")
st.set_page_config(
    page_title="SIN Enterprise Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# --- Helper Functions ---
def fetch_stats():
    try:
        response = requests.get(f"{API_URL}/dashboard/stats")
        if response.status_code == 200:
            return response.json()
    except:
        return None

def fetch_devices():
    try:
        response = requests.get(f"{API_URL}/devices")
        if response.status_code == 200:
            return pd.DataFrame(response.json())
    except:
        return pd.DataFrame()

# --- UI Layout ---
st.title("🛡️ SIN: Shadows In The Network")
st.markdown("### Enterprise IoT Security Overseer")

# Sidebar
st.sidebar.header("Control Center")
if st.sidebar.button("🔄 Refresh Data"):
    st.rerun()

# NEW: REPORT GENERATION BUTTON
st.sidebar.markdown("---")
st.sidebar.subheader("Audit Reports")
if st.sidebar.button("📄 Generate PDF Report"):
    with st.spinner("Generating Security Audit..."):
        # 1. Fetch latest data
        df = fetch_devices()
        if not df.empty:
            # 2. Convert DataFrame to list of dicts for the report generator
            devices_list = df.to_dict('records')
            
            # 3. Generate PDF
            pdf_path = generate_pdf_report(devices_list)
            
            # 4. Create Download Button
            with open(pdf_path, "rb") as pdf_file:
                pdf_bytes = pdf_file.read()
                
            st.sidebar.download_button(
                label="⬇️ Download Audit PDF",
                data=pdf_bytes,
                file_name="sin_security_audit.pdf",
                mime="application/pdf"
            )
            st.sidebar.success("Report Generated!")
        else:
            st.sidebar.error("No data to report on.")

st.sidebar.markdown("---")
st.sidebar.info(f"**System Status**: 🟢 Online\n\n**API**: {API_URL}")

# 1. Top Level Metrics
stats = fetch_stats()
col1, col2, col3 = st.columns(3)

if stats:
    col1.metric("Total Assets", stats.get('total_assets_tracked', 0))
    col2.metric("Total Scans Run", stats.get('total_scan_runs', 0))
    col3.metric("Last Activity", str(stats.get('latest_activity', 'N/A'))[:19])
else:
    st.error("⚠️ API Offline. Please run: uvicorn sin.api.server:app")

st.markdown("---")

# 2. Main Data View
df = fetch_devices()

if not df.empty:
    # Charts Row
    c1, c2 = st.columns(2)
    
    with c1:
        st.subheader("📡 Device Vendor Distribution")
        df['vendor'] = df['vendor'].fillna('Unknown')
        fig_vendor = px.pie(df, names='vendor', hole=0.4)
        st.plotly_chart(fig_vendor, use_container_width=True)

    with c2:
        st.subheader("🖥️ OS Family Distribution")
        df['os_family'] = df['os_family'].fillna('Unknown')
        fig_os = px.bar(df['os_family'].value_counts(), orientation='h')
        st.plotly_chart(fig_os, use_container_width=True)

    # Detailed Table
    st.subheader("🗂️ Live Asset Inventory")
    
    display_df = df[['ip_address', 'hostname', 'status', 'vendor', 'os_family', 'open_ports']]
    st.dataframe(
        display_df,
        column_config={
            "ip_address": "IP Address",
            "open_ports": st.column_config.ListColumn("Open Ports"),
            "status": st.column_config.TextColumn("State"),
        },
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No device data found. Run a scan agent to populate data.")
