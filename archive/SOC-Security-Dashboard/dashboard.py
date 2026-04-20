import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from streamlit_autorefresh import st_autorefresh

st.set_page_config(page_title="SOC Security Monitoring Dashboard", layout="wide")

st.title("SOC Security Monitoring Dashboard")

# Sidebar controls for real-time behavior
st.sidebar.header("Live Settings")
refresh_seconds = st.sidebar.slider(
    "Auto-refresh interval (seconds)",
    min_value=5,
    max_value=60,
    value=10,
    step=5,
    help="How often the dashboard should re-read the latest logs.",
)
time_window_label = st.sidebar.selectbox(
    "Time window",
    ["Last 15 minutes", "Last 1 hour", "Last 24 hours", "All data"],
    index=2,
)

# Trigger automatic reruns at the chosen interval
st_autorefresh(interval=refresh_seconds * 1000, key="soc_dashboard_autorefresh")

# Load latest security logs on every rerun
df = pd.read_csv("SOC-Security-Dashboard/security_logs.csv")

# Basic parsing and enrichment for SOC use
if "timestamp" in df.columns:
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
else:
    df["timestamp"] = datetime.now()


def map_severity(event_type: str) -> str:
    if not isinstance(event_type, str):
        return "Low"
    et = event_type.upper()
    if "MALWARE" in et:
        return "Critical"
    if "SUSPICIOUS" in et:
        return "High"
    if "FAILED_LOGIN" in et or "FAILED" in et:
        return "Medium"
    return "Low"


df["severity"] = df["event_type"].apply(map_severity)

# Apply time window filter
now = df["timestamp"].max() if not df.empty else datetime.now()
if time_window_label == "Last 15 minutes":
    start_time = now - timedelta(minutes=15)
elif time_window_label == "Last 1 hour":
    start_time = now - timedelta(hours=1)
elif time_window_label == "Last 24 hours":
    start_time = now - timedelta(hours=24)
else:
    start_time = None

if start_time is not None:
    df = df[df["timestamp"] >= start_time]

# Event type filter so a small team can focus on what matters
event_types = sorted(df["event_type"].unique())
selected_event_types = st.sidebar.multiselect(
    "Event types to display",
    options=event_types,
    default=event_types,
)
if selected_event_types:
    df = df[df["event_type"].isin(selected_event_types)]

st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# Top-level SOC metrics for a small team
st.subheader("Current Security Posture")
col1, col2, col3, col4 = st.columns(4)
total_alerts = len(df)
critical_alerts = (df["severity"] == "Critical").sum()
high_alerts = (df["severity"] == "High").sum()
unique_sources = df["source_ip"].nunique() if "source_ip" in df.columns else 0

col1.metric("Total alerts (filtered)", total_alerts)
col2.metric("Critical alerts", critical_alerts)
col3.metric("High alerts", high_alerts)
col4.metric("Unique source IPs", unique_sources)

st.divider()

# Distribution charts
left_col, right_col = st.columns(2)
with left_col:
    st.subheader("Event Type Distribution")
    event_counts = df["event_type"].value_counts()
    st.bar_chart(event_counts)

with right_col:
    st.subheader("Severity Distribution")
    severity_counts = df["severity"].value_counts()
    st.bar_chart(severity_counts)

st.divider()

# Active high/critical alerts in recent window
if "timestamp" in df.columns and not df.empty:
    recent_window = now - timedelta(minutes=15)
    recent_df = df[df["timestamp"] >= recent_window]
    active_alerts = recent_df[recent_df["severity"].isin(["High", "Critical"])]

    st.subheader("Active High / Critical Alerts (last 15 minutes)")
    if not active_alerts.empty:
        st.dataframe(
            active_alerts.sort_values("timestamp", ascending=False)[
                ["timestamp", "event_type", "severity", "source_ip", "username", "status"]
                if all(col in active_alerts.columns for col in ["source_ip", "username", "status"])
                else active_alerts.columns
            ]
        )
    else:
        st.success("No high or critical alerts in the last 15 minutes.")

st.subheader("Recent Security Events")
recent_events = df.sort_values("timestamp", ascending=False).head(50)
st.dataframe(recent_events)

st.info(
    "This real-time dashboard is designed for a small security team to monitor live security events, "
    "focus on high/critical alerts, and collaborate on active incidents."
)
