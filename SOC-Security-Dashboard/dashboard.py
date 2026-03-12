import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.title("SOC Security Monitoring Dashboard")

# Load security logs
df = pd.read_csv("security_logs.csv")

# Event counts
event_counts = df['event_type'].value_counts()

st.subheader("Security Event Distribution")

fig, ax = plt.subplots()
event_counts.plot(kind='bar', ax=ax)
plt.xlabel("Event Type")
plt.ylabel("Count")

st.pyplot(fig)

# Show raw logs
st.subheader("Security Logs")

st.dataframe(df)

