
import streamlit as st
import pandas as pd
import requests
import os
from datetime import datetime
import plotly.express as px

# --- Configurazione
REFERENCE_DATE_STR = "2025-10-01"
DELIVERY_DATE_STR = "2025-10-17"
REFERENCE_DATE = pd.to_datetime(REFERENCE_DATE_STR)
DELIVERY_DATE = pd.to_datetime(DELIVERY_DATE_STR)
THRESHOLD = 0.1

DATA_PATH = "team_selection"
CACHE_PATH = "cache_epss"
if not os.path.exists(CACHE_PATH):
    os.makedirs(CACHE_PATH)
if not os.path.exists(DATA_PATH):
    os.makedirs(DATA_PATH)

st.set_page_config(page_title="CVE Selection", layout="wide")
st.title("Tracking selected CVEs for each team")


group_files = {}
for fname in os.listdir(DATA_PATH):
    if not fname.endswith(".csv"):
        continue
    group_files[fname.replace(".csv", "")] = fname

@st.cache_data(ttl=60)
def load_all_groups(group_files_dict):
    dfs = []
    team_count = 0
    for group_name, file_name in group_files_dict.items():
        path = os.path.join(DATA_PATH, file_name)
        if os.path.exists(path):
            df = pd.read_csv(path)
            df = df.rename(columns={"cve.id": "CVE"})
            df["Team"] = group_name
            dfs.append(df)
            team_count += 1
    if dfs:
        print(f"Loaded selection for {team_count} teams.")
        return pd.concat(dfs, ignore_index=True)
    print("No team selection files found.")
    return pd.DataFrame()

df_selected = load_all_groups(group_files)


@st.cache_data(ttl=60)
def get_epss_history():
    all_data = []
    for file_name in [x for x in sorted(os.listdir(CACHE_PATH))]:
        if not file_name.endswith('csv'): 
            continue
        if file_name.startswith('cvss'): 
            continue
        path = os.path.join(CACHE_PATH, file_name)
        print(path)
        if os.path.exists(path):
            df = pd.read_csv(path)
            df = df.drop(columns = 'cve.id', errors='ignore')
            df = df.rename(columns={"cvss_baseScore": "daily_cvss_baseScore"})
        all_data.append(df)

    final_df = pd.concat(all_data, ignore_index=True)
    final_df.rename(columns={"cve": "CVE"}, inplace=True)
    final_df["timestamp"] = pd.to_datetime(final_df["timestamp"])
    final_df["epss"] = pd.to_numeric(final_df["epss"], errors="coerce")
    return final_df


# --- EPSS historical data
df_all = get_epss_history()

df_all.to_csv("debug_all_epss_history.csv", index=False)
df_selected.to_csv("debug_selected_cves.csv", index=False)

# --- Join metadata and team selection
df_selected = df_selected.drop(columns=["epss", "percentile"], errors="ignore")
df_all = pd.merge(df_all, df_selected, on="CVE", how="right", validate="many_to_many")
df_all["description_short"] = df_all["description"].astype(str).apply(
    lambda x: x[:100] + "..." if len(x) > 100 else x)

df_all["nvd_url"] = df_all["CVE"].apply(lambda x: f'https://nvd.nist.gov/vuln/detail/{x}')

df_all.to_csv("debug_merge.csv", index=False)


# --- Filter for visualization
available_groups = df_selected["Team"].unique().tolist()
chosen_group = st.selectbox("Select a team name", available_groups)
df_filtered = df_all[df_all["Team"] == chosen_group]

# --- EPSS over time
st.subheader("EPSS over time for selected CVEs")

fig = px.line(
    df_filtered,
    x="timestamp",
    y="epss",
    color="CVE",
    hover_data={
        "CVE": True,
        "epss": True,
        "description_short": True,
        "cvss_baseScore": True,
        "cvss_vectorString": True,
    },
    title=f"EPSS over time for selected CVEs – {chosen_group}"
)

fig.update_layout(
    height=500,
    legend_title_text="CVE",
    xaxis_title="Date",
    yaxis_title="EPSS",
    hovermode="closest",
#    yaxis=dict(type="log"),
#    yaxis_range=[0.0000001,1]
)

st.plotly_chart(fig, width="stretch")

# --- Summary statistics
def get_epss_summary(df, ref_date):
    summary_data = []
    for (team, cve), cve_df in df.groupby(["Team", "CVE"], dropna=False):
        cve_df = cve_df.sort_values("timestamp")
        cve_df = cve_df[cve_df["timestamp"] >= ref_date]
        if cve_df.empty:
            continue
        epss_start = cve_df.iloc[0]["epss"]
        if pd.isna(epss_start):
            continue
        pct_start = cve_df.iloc[0]["percentile"]
        pct_subset_start = cve_df.iloc[0]["percentile_subset"]
        if pd.isna(epss_start):
            continue
        cve_df["delta_pct"] = cve_df["percentile_subset"] - pct_subset_start
        cve_df["delta_epss"] = cve_df["epss"] - epss_start
        pct_avg_gain = cve_df["delta_pct"].mean()
        pct_max_gain = cve_df["delta_pct"].max()
        epss_avg_gain = cve_df["delta_epss"].mean()
        epss_max_gain = cve_df["delta_epss"].max()
        summary_data.append({
            "CVE": cve,
            "NVD": cve_df["nvd_url"].iloc[0],
            "Team": cve_df["Team"].iloc[0],
            "Initial CVSS": f'{cve_df.iloc[0].cvss_baseScore}',
            "Current CVSS": f'{cve_df.iloc[-1].daily_cvss_baseScore}',
            "Initial EPSS": epss_start,
            "Current EPSS": cve_df.iloc[-1]["epss"],
            "Initial PCT": pct_start,
            "Current PCT": cve_df.iloc[-1]["percentile"],
            "Initial PCT (subset)": pct_subset_start,
            "Current PCT (subset)": cve_df.iloc[-1]["percentile_subset"],
            "EPSS: Avg gain": epss_avg_gain,
            "EPSS: Max gain": epss_max_gain,
        })
    return pd.DataFrame(summary_data)


eval_date = REFERENCE_DATE
summary_df = get_epss_summary(df_all, eval_date)

filtered_summary = summary_df[summary_df["Team"] == chosen_group]

# --- CVE tables with summary statistics
st.subheader("CVE summary statistics")
st.dataframe(
    filtered_summary,
    column_config={
    "NVD": st.column_config.LinkColumn(
        "NVD",           
        display_text="🔗"  
    )},
    hide_index=True,
    width="stretch")



# --- Leaderboard
st.subheader(f"🏆 Teams Leaderboard - Reference date {eval_date.strftime('%Y-%m-%d')}")

leaderboard = (
    summary_df.groupby("Team")
    .agg({
        "EPSS: avg gain": "mean",
        "EPSS: max gain": "max",
        })
    .reset_index()
    .sort_values("EPSS: max gain", ascending=False)
)

st.dataframe(leaderboard, width="stretch")
