import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px

# Define function to load data from SQLite database
def load_data():
    conn = sqlite3.connect('../data/scan_results.db')
    df = pd.read_sql('SELECT * FROM findings', conn)
    conn.close()
    return df

# Dashboard title and header
st.title("AWS Misconfiguration Detector")
st.subheader("Scan Findings Dashboard")

# Load scan findings from database
df = load_data()

# Display selected columns in findings table
st.dataframe(df[['resource_name', 'resource_type', 'risk_rating', 'label', 'remediation']], use_container_width=True)

# Visualization 1
# Bar chart of findings grouped by risk level
st.subheader("Findings by Risk Level")

risk_counts = df['risk_rating'].value_counts().reset_index()
risk_counts.columns = ['risk_rating', 'count']

# Define risk level order
risk_order = ['Low', 'Medium', 'High', 'Critical']

# Sort risk counts by defined order
risk_counts['risk_rating'] = pd.Categorical(risk_counts['risk_rating'], categories=risk_order, ordered=True)
risk_counts = risk_counts.sort_values('risk_rating')

fig = px.bar(
    risk_counts,
    x='risk_rating',
    y='count',
    color='risk_rating',
    color_discrete_map={
        'Low': 'green',
        'Medium': 'orange',
        'High': 'red',
        'Critical': 'darkred'
    }
)

st.plotly_chart(fig)

# Visualization 2
# Grouped bar chart of compliant vs misconfigured resources per AWS service
st.subheader("Compliance Scores per AWS Service")
compliance = df.groupby(['resource_type', 'label']).size().reset_index(name='count')

fig2 = px.bar(
    compliance,
    x='resource_type',
    y='count',
    color='label',
    barmode='group',
    color_discrete_map={
        'compliant': 'green',
        'misconfigured': 'red'
    }
)

st.plotly_chart(fig2)

# Visualization 3
# Line chart showing misconfiguration trends over time
st.subheader("Misconfiguration Trends Over Time")

# Convert timestamp to datetime
df['timestamp'] = pd.to_datetime(df['timestamp'])

# Filter only misconfigured findings
misconfigured = df[df['label'] == 'misconfigured']

# Group by timestamp and count findings
trends = misconfigured.groupby('timestamp').size().reset_index(name='count')

fig3 = px.line(
    trends,
    x='timestamp',
    y='count',
    markers=True
)

st.plotly_chart(fig3)