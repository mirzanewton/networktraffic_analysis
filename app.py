import streamlit as st
import pandas as pd
import tempfile
import json
import os
from datetime import datetime

from nids.pcap_reader import read_packets
from nids.decode import decode
from nids.detectors import run_all
from nids.report import compute_stats

# ---------------- PAGE SETTINGS ----------------

st.set_page_config(
    page_title="Sentinel | Network IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------- CUSTOM DESIGN ----------------

st.markdown("""
<style>
.stApp {
    background: #0b1020;
    color: #e5e7eb;
}

[data-testid="stSidebar"] {
    background: #151b35;
    border-right: 1px solid #293454;
}

[data-testid="stSidebar"] * {
    color: #e5e7eb;
}

.main-title {
    font-size: 30px;
    font-weight: 800;
    color: #ffffff;
}

.subtitle {
    color: #94a3b8;
    font-size: 14px;
}

.metric-card {
    background: linear-gradient(135deg, #192442, #202c4d);
    border: 1px solid #33446b;
    border-radius: 13px;
    padding: 19px;
    min-height: 112px;
}

.metric-label {
    color: #a5b4d4;
    font-size: 13px;
}

.metric-value {
    color: #ffffff;
    font-size: 29px;
    font-weight: 800;
    margin-top: 8px;
}

.section-title {
    color: #ffffff;
    font-size: 19px;
    font-weight: 700;
    margin-top: 18px;
}

.status-card {
    background: #17243b;
    border: 1px solid #294263;
    border-radius: 12px;
    padding: 15px;
}

div[data-testid="stMetric"] {
    background: #192442;
    border: 1px solid #33446b;
    padding: 14px;
    border-radius: 12px;
}

div[data-testid="stMetric"] label {
    color: #a5b4d4 !important;
}

div[data-testid="stMetric"] [data-testid="stMetricValue"] {
    color: white !important;
}

h1, h2, h3 {
    color: white !important;
}

.stButton button {
    background: #635bdb;
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
}

.stButton button:hover {
    background: #8179f5;
    color: white;
}

hr {
    border-color: #293454;
}
</style>
""", unsafe_allow_html=True)

# ---------------- SIDEBAR ----------------

with st.sidebar:
    st.markdown("## 🛡️ SENTINEL IDS")
    st.caption("NETWORK SECURITY MONITOR")

    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "Dashboard",
            "Security Alerts",
            "Traffic Analysis",
            "Reports"
        ]
    )

    st.divider()

    st.markdown("### SYSTEM STATUS")
    st.success("Application running")

    st.caption("Analysis mode: Offline PCAP")
    st.caption("Detection engine: Python IDS")

# ---------------- HEADER ----------------

st.markdown(
    '<div class="main-title">Network Security Dashboard</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">Network Traffic Analysis & Intrusion Detection System</div>',
    unsafe_allow_html=True
)

st.write("")

# ---------------- SESSION STATE ----------------

if "analysis" not in st.session_state:
    st.session_state.analysis = None

if "analysis_name" not in st.session_state:
    st.session_state.analysis_name = None

# ---------------- ANALYSIS FUNCTION ----------------

def analyse_capture(file_path, file_name):

    packets = []

    for timestamp, linktype, raw in read_packets(file_path):
        packet = decode(timestamp, linktype, raw)

        if packet:
            packets.append(packet)

    alerts = run_all(packets)
    stats = compute_stats(packets)

    st.session_state.analysis = {
        "packets": packets,
        "alerts": alerts,
        "stats": stats
    }

    st.session_state.analysis_name = file_name


# ---------------- FILE UPLOAD ----------------

st.markdown("### 📂 Network Capture Analysis")

col1, col2 = st.columns([2, 1])

with col1:
    uploaded_file = st.file_uploader(
        "Upload PCAP / PCAPNG file",
        type=["pcap", "pcapng"]
    )

with col2:
    st.write("")
    st.write("")
    sample_button = st.button(
        "🔍 Analyse Sample Capture",
        use_container_width=True
    )

upload_button = st.button(
    "▶ Analyse Uploaded Capture",
    use_container_width=True,
    disabled=uploaded_file is None
)

# ---------------- PROCESS SAMPLE ----------------

if sample_button:

    sample_path = os.path.join(
        os.path.dirname(__file__),
        "sample",
        "sample.pcap"
    )

    if os.path.exists(sample_path):
        try:
            with st.spinner("Analysing sample network traffic..."):
                analyse_capture(sample_path, "sample.pcap")
            st.success("Sample capture analysed successfully!")
        except Exception as error:
            st.error(f"Analysis failed: {error}")
    else:
        st.error("sample.pcap was not found in the sample folder.")

# ---------------- PROCESS UPLOAD ----------------

if upload_button and uploaded_file is not None:

    suffix = os.path.splitext(uploaded_file.name)[1]

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix
        ) as temp_file:

            temp_file.write(uploaded_file.getvalue())
            temp_path = temp_file.name

        with st.spinner("Analysing uploaded network traffic..."):
            analyse_capture(temp_path, uploaded_file.name)

        st.success("Network capture analysed successfully!")

    except Exception as error:
        st.error(f"Analysis failed: {error}")

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

# ---------------- RESULTS ----------------

result = st.session_state.analysis

if result is None:

    st.info(
        "Upload a network capture or analyse the included sample "
        "to view security analytics."
    )

    st.markdown("### What this dashboard monitors")

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown("#### 🌐 Network Traffic")
        st.caption("Packet and protocol statistics")

    with c2:
        st.markdown("#### 🚨 Threat Detection")
        st.caption("Suspicious activity identified by IDS rules")

    with c3:
        st.markdown("#### 📊 Security Reports")
        st.caption("Downloadable analysis results")

    st.stop()

# ---------------- GET REAL DATA ----------------

stats = result["stats"]
alerts = result["alerts"]

total_packets = stats["packets"]
total_bytes = stats["bytes"]

high = sum(
    1 for a in alerts
    if str(a.severity).upper() == "HIGH"
)

medium = sum(
    1 for a in alerts
    if str(a.severity).upper() == "MEDIUM"
)

low = sum(
    1 for a in alerts
    if str(a.severity).upper() == "LOW"
)

first = stats["first"]
last = stats["last"]

duration = 0

if first is not None and last is not None:
    duration = max(0, last - first)

# Prepare alert table
alert_rows = []

for alert in alerts:
    alert_rows.append({
        "Detection Rule": alert.rule,
        "Severity": str(alert.severity).upper(),
        "Source IP": alert.src,
        "Destination IP": alert.dst,
        "Description": alert.detail,
        "MITRE Technique": alert.mitre
    })

alert_df = pd.DataFrame(alert_rows)

# ---------------- DASHBOARD PAGE ----------------

if page == "Dashboard":

    st.markdown("## 📊 Security Overview")

    st.caption(
        f"Currently displaying results for: {st.session_state.analysis_name}"
    )

    # Metric cards

    m1, m2, m3, m4 = st.columns(4)

    with m1:
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-label">TOTAL PACKETS</div>'
            f'<div class="metric-value">{total_packets:,}</div>'
            f'</div>',
            unsafe_allow_html=True
        )

    with m2:
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-label">TOTAL BYTES</div>'
            f'<div class="metric-value">{total_bytes:,}</div>'
            f'</div>',
            unsafe_allow_html=True
        )

    with m3:
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-label">DETECTED ALERTS</div>'
            f'<div class="metric-value">{len(alerts):,}</div>'
            f'</div>',
            unsafe_allow_html=True
        )

    with m4:
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-label">CAPTURE DURATION</div>'
            f'<div class="metric-value">{duration:.2f}s</div>'
            f'</div>',
            unsafe_allow_html=True
        )

    st.write("")

    # Severity cards

    st.markdown("### 🚨 Threat Severity")

    s1, s2, s3 = st.columns(3)

    s1.metric("🔴 High Severity", high)
    s2.metric("🟠 Medium Severity", medium)
    s3.metric("🟢 Low Severity", low)

    st.divider()

    # Charts

    st.markdown("### 📈 Network Analytics")

    left, right = st.columns(2)

    with left:
        st.markdown("#### Protocol Distribution")

        protocol_data = pd.DataFrame(
            list(stats["protocols"].items()),
            columns=["Protocol", "Packets"]
        )

        if not protocol_data.empty:
            st.bar_chart(
                protocol_data.set_index("Protocol"),
                color="#7167f5"
            )
        else:
            st.info("No protocol information available.")

    with right:
        st.markdown("#### Top Network Talkers")

        talker_data = pd.DataFrame(
            list(stats["talkers"].items()),
            columns=["IP Address", "Packets"]
        )

        if not talker_data.empty:
            talker_data = talker_data.head(10)

            st.bar_chart(
                talker_data.set_index("IP Address"),
                color="#16b8a6"
            )
        else:
            st.info("No network talker information available.")

    st.divider()

    st.markdown("### 🛡️ Recent Security Alerts")

    if not alert_df.empty:
        st.dataframe(
            alert_df.head(10),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.success("No security alerts were detected.")

    st.caption(
        "All displayed values are calculated from the selected PCAP capture."
    )

# ---------------- ALERTS PAGE ----------------

elif page == "Security Alerts":

    st.markdown("## 🚨 Security Alerts")

    st.metric("Total Detected Alerts", len(alerts))

    if not alert_df.empty:

        severity_filter = st.selectbox(
            "Filter by severity",
            ["ALL", "HIGH", "MEDIUM", "LOW"]
        )

        filtered = alert_df.copy()

        if severity_filter != "ALL":
            filtered = filtered[
                filtered["Severity"] == severity_filter
            ]

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.success("No alerts detected in this capture.")

# ---------------- TRAFFIC ANALYSIS PAGE ----------------

elif page == "Traffic Analysis":

    st.markdown("## 🌐 Traffic Analysis")

    st.markdown("### Protocol Statistics")

    protocol_data = pd.DataFrame(
        list(stats["protocols"].items()),
        columns=["Protocol", "Packets"]
    )

    if not protocol_data.empty:

        st.bar_chart(
            protocol_data.set_index("Protocol"),
            color="#7167f5"
        )

        st.dataframe(
            protocol_data,
            use_container_width=True,
            hide_index=True
        )

    st.markdown("### Top Network Talkers")

    talker_data = pd.DataFrame(
        list(stats["talkers"].items()),
        columns=["IP Address", "Packets"]
    )

    if not talker_data.empty:

        st.bar_chart(
            talker_data.head(10).set_index("IP Address"),
            color="#16b8a6"
        )

        st.dataframe(
            talker_data.head(10),
            use_container_width=True,
            hide_index=True
        )

# ---------------- REPORTS PAGE ----------------

elif page == "Reports":

    st.markdown("## 📄 Security Analysis Reports")

    st.write(
        f"Capture analysed: {st.session_state.analysis_name}"
    )

    st.metric("Total Alerts", len(alerts))

    json_report = json.dumps(
        alert_rows,
        indent=4,
        default=str
    )

    markdown_report = (
        "# Network Traffic Analysis & IDS Report\n\n"
        f"Capture: {st.session_state.analysis_name}\n\n"
        f"Generated: {datetime.now().isoformat(timespec='seconds')}\n\n"
        f"Total packets: {total_packets}\n\n"
        f"Total bytes: {total_bytes}\n\n"
        f"Capture duration: {duration:.2f} seconds\n\n"
        f"Total alerts: {len(alerts)}\n\n"
        f"High severity: {high}\n\n"
        f"Medium severity: {medium}\n\n"
        f"Low severity: {low}\n\n"
        "## Detected Alerts\n\n"
    )

    for row in alert_rows:

        markdown_report += (
            f"### {row['Detection Rule']}\n\n"
            f"- Severity: {row['Severity']}\n"
            f"- Source IP: {row['Source IP']}\n"
            f"- Destination IP: {row['Destination IP']}\n"
            f"- Description: {row['Description']}\n"
            f"- MITRE Technique: {row['MITRE Technique']}\n\n"
        )

    c1, c2 = st.columns(2)

    with c1:
        st.download_button(
            "⬇ Download JSON Report",
            data=json_report,
            file_name="network_ids_alerts.json",
            mime="application/json",
            use_container_width=True
        )

    with c2:
        st.download_button(
            "⬇ Download Markdown Report",
            data=markdown_report,
            file_name="network_ids_report.md",
            mime="text/markdown",
            use_container_width=True
        )

    if not alert_df.empty:
        st.markdown("### Report Preview")
        st.dataframe(
            alert_df,
            use_container_width=True,
            hide_index=True
        )

# ---------------- FOOTER ----------------

st.divider()

st.caption(
    "SENTINEL IDS | Network Traffic Analysis & Intrusion Detection | "
    "Offline PCAP Analysis"
)