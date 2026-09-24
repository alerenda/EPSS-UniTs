
import streamlit as st
import pandas as pd
import requests
import os
from datetime import datetime
import plotly.express as px

# --- Configurazione
REFERENCE_DATE_STR = "2026-09-20"
DELIVERY_DATE_STR = "2026-09-22"
REFERENCE_DATE = pd.to_datetime(REFERENCE_DATE_STR)
DELIVERY_DATE = pd.to_datetime(DELIVERY_DATE_STR)
THRESHOLD = 0.1

DATA_PATH = "team_selection"
CACHE_PATH = "cache_epss"
HISTORY_TIMESERIES_FILE = "team_history_timeseries.csv"
METADATA_FILE = "team_cve_metadata.csv"

if not os.path.exists(CACHE_PATH):
    os.makedirs(CACHE_PATH)
if not os.path.exists(DATA_PATH):
    os.makedirs(DATA_PATH)

group_files = {}
for fname in os.listdir(DATA_PATH):
    if not fname.endswith(".csv"):
        continue
    group_files[fname.replace(".csv", "")] = fname


@st.cache_data(ttl=3600)
def load_epss_data():
    df_history = pd.read_csv(HISTORY_TIMESERIES_FILE)
    df_metadata = pd.read_csv(METADATA_FILE)
    return df_history.merge(df_metadata, on=["Team", "CVE"], how="left", validate="many_to_one")

    

# --- EPSS historical data
df_epss_history = load_epss_data()

# --- Summary statistics
def get_epss_summary(df, ref_date):
    summary_data = []
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    for (team, cve), cve_df in df.groupby(["Team", "CVE"], dropna=False):
        cve_df = cve_df.sort_values("timestamp")
        cve_df = cve_df[cve_df["timestamp"] >= ref_date]
        if cve_df.empty:
            continue
        epss_start = cve_df.iloc[0]["epss"]
        if pd.isna(epss_start):
            continue
        pct_start = cve_df.iloc[0]["percentile"]
        # pct_subset_start = cve_df.iloc[0]["percentile_subset"]
        if pd.isna(epss_start):
            continue
        # cve_df["delta_pct"] = cve_df["percentile_subset"] - pct_subset_start
        cve_df["delta_epss"] = cve_df["epss"] - epss_start
        # pct_avg_gain = cve_df["delta_pct"].mean()
        # pct_max_gain = cve_df["delta_pct"].max()
        epss_avg_gain = cve_df["delta_epss"].mean()
        # epss_max_gain = cve_df["delta_epss"].max()
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
          #  "Initial PCT (subset)": pct_subset_start,
          #  "Current PCT (subset)": cve_df.iloc[-1]["percentile_subset"],
            "EPSS: Avg change": epss_avg_gain,
          #  "EPSS: Max gain": epss_max_gain,
          #  "PCT: Avg gain": pct_avg_gain,
          #  "PCT: Max gain": pct_max_gain,
        })
    return pd.DataFrame(summary_data)



st.set_page_config(page_title="CVE Selection", layout="wide")
st.title("FantaCVE: Predict the next high-EPSS vulnerabilities")

primary = st.get_option("theme.primaryColor")

st.markdown("""
### How does it work
- **One dataset**, consisting of **XXX CVEs** published between YYYY/MM/DD and YYYY/MM/DD, sourced from [NVD](https://nvd.nist.gov).
- Each student selected 10 CVEs and submitted their picks on YYYY/MM/DD ("Reference Date").
- EPSS values for all selected CVEs are **updated daily**.
- The final **leaderboard** will be evaluated on YYYY/MM/DD.
""")


tab1, tab2 = st.tabs(["📈 Team selection", "🏆 Leaderboard"])
with tab1:
    available_groups = df_epss_history["Team"].unique().tolist()

    chosen_group = st.selectbox("Select a team name", available_groups)
    df_filtered = df_epss_history[df_epss_history["Team"] == chosen_group]
    df_filtered["timestamp"] = pd.to_datetime(df_filtered["timestamp"])

    eval_date = DELIVERY_DATE
    summary_df = get_epss_summary(df_epss_history, eval_date)

    filtered_summary = summary_df[summary_df["Team"] == chosen_group]

    st.subheader("Tracking EPSS values of selected CVEs")
    y_scale_option = st.radio(
        "Select y-axis scale",
        ["auto", "up to 0.01", "up to 0.1", "up to 1"],
        horizontal=True
    )



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
        #title=f"{chosen_group}: EPSS over time for selected CVEs"
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

    if y_scale_option == "up to 0.01":
        fig.update_yaxes(range=[0, 0.01])
    elif y_scale_option == "up to 0.1":
        fig.update_yaxes(range=[0, 0.1])
    elif y_scale_option == "up to 1":
        fig.update_yaxes(range=[0, 1])
  
    fig.add_vline(
        x=eval_date,
        line_width=0.5,
        line_dash="dash",
        line_color="gray",
    )
    fig.add_annotation(
        x=eval_date,
        y=1,
        xref="x",
        yref="paper",
        text="Reference Date",
        showarrow=False,
        xanchor="left",
        yanchor="bottom"
    )

    st.plotly_chart(fig, width="stretch")



    # --- CVE tables with summary statistics
    st.subheader(f"{chosen_group}: Selected CVEs and summary statistics")
    st.dataframe(
        filtered_summary.drop(columns=["CVE","Team"]),
        column_config={
        "NVD": st.column_config.LinkColumn(
            "CVE",           
            display_text=r".*/(CVE-\d{4}-\d+)$"
        )},
        hide_index=True,
        width="stretch")

with tab2:

    # --- Leaderboard
    st.subheader(f"Reference date {eval_date.strftime('%Y-%m-%d')}")

    leaderboard = (
        summary_df.groupby("Team")
        .agg({
            "EPSS: Avg change": "sum",
            })
        .reset_index()
        .sort_values("EPSS: Avg change", ascending=False)
    )



    height = 35 * (len(leaderboard) + 1)

    st.dataframe(
        leaderboard,
        hide_index=True,
        height=height,   
        width="content"
    )

st.markdown("""
<style>
.footer {
    position: relative;
    margin-top: 50px;
    padding: 15px;
    background-color: var(--secondary-background-color);
    color: var(--text-color);
    border-radius: 8px;
    text-align: center;
    font-size: 14px;
}
</style>

<div class="footer">
    This activity was carried out within the <a href="https://alerenda.github.io/teaching/cybersecurity/" target="_blank">Cybersecurity LAB</a> course of the 
   <a href="https://degree.units.it/en/0320107303300001" target="_blank">Computer Engineering MSc</a> program at the University of Trieste.
</div>
""", unsafe_allow_html=True)
