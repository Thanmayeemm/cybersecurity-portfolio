import streamlit as st
import pandas as pd

st.set_page_config(page_title="SOC Security Monitoring Dashboard", layout="wide")

st.title("SOC Security Monitoring Dashboard")

# Correct path for Streamlit Cloud
df = pd.read_csv("SOC-Security-Dashboard/security_logs.csv")

st.subheader("Security Event Distribution")
st.bar_chart(df["event_type"].value_counts())

st.subheader("Recent Security Events")
st.dataframe(df.tail(20))
