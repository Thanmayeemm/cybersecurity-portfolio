import streamlit as st
import pandas as pd
import time

st.title("SOC Real-Time Security Monitoring Dashboard")

df = pd.read_csv("SOC-Security-Dashboard/security_logs.csv")

event_counts = df["event_type"].value_counts()

st.subheader("Security Event Distribution")
st.bar_chart(event_counts)

st.subheader("Recent Security Events")
st.dataframe(df.tail(20))

st.write("Dashboard refreshes every 5 seconds")

time.sleep(5)
st.experimental_rerun()
