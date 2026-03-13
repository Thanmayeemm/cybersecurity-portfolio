import streamlit as st
import pandas as pd
import time

st.title("SOC Security Monitoring Dashboard")

# Load log data
df = pd.read_csv("security_logs.csv")

# Show event distribution
st.subheader("Security Event Distribution")
event_counts = df["event_type"].value_counts()
st.bar_chart(event_counts)

# Show latest events
st.subheader("Recent Security Events")
st.dataframe(df.tail(20))

st.write("Dashboard refreshes every 5 seconds")

time.sleep(5)
st.rerun()
