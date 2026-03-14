import streamlit as st
import pandas as pd

st.title("SOC Security Monitoring Dashboard")

# Correct path for Streamlit Cloud
df = pd.read_csv("SOC-Security-Dashboard/security_logs.csv")

st.subheader("Security Event Distribution")
event_counts = df["event_type"].value_counts()
st.bar_chart(event_counts)

st.subheader("Recent Security Events")
st.dataframe(df.tail(20))

st.info("This dashboard displays simulated SOC security logs.")
