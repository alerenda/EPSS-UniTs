
import pandas as pd
import requests
import os
from datetime import datetime

REFERENCE_DATE_STR = "2026-10-15"
TEAM_PATH = "team_selection"
CACHE_PATH = "cache_epss"
DATA_PATH = "all_cves"  
FILENAME = "vuln_2026_09_id.csv"
HISTORY_TIMESERIES_FILE = "team_history_timeseries.csv"
METADATA_FILE = "team_cve_metadata.csv"
# Student-provided fields used by the dashboard; EPSS comes from the daily cache.
TEAM_SELECTION_COLUMNS = ["cve.id", "description", "cvss_baseScore", "cvss_vectorString"]
URL = "https://api.first.org/data/v1/epss"


if not os.path.exists(CACHE_PATH):
    os.makedirs(CACHE_PATH)

def fetch_historical_data(cve_list, start_date=REFERENCE_DATE_STR):
    start = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.today()
    count_save = 0

    for single_date in pd.date_range(start, end):
        date_str = single_date.strftime("%Y-%m-%d")
        cache_file = os.path.join(CACHE_PATH,f"cache_epss_date_{date_str}.csv")

        if not os.path.exists(cache_file):
            daily_df = pd.DataFrame(columns=["cve", "epss", "percentile", "percentile_subset", "timestamp"])
            chunk_size = 100
            for start in range(0, len(cve_list), chunk_size):
                cve_chunk = cve_list[start:start + chunk_size]
                cve_str = ",".join(cve_chunk)
                params = {"cve": cve_str, "date": date_str}
                r = requests.get(URL, params=params)
                if r.status_code == 200:
                    tmp_df = pd.DataFrame(r.json().get("data", []))
                    tmp_df["timestamp"] = date_str
                    daily_df = pd.concat([daily_df, tmp_df], ignore_index=True)
                else:
                    print(f"Failed to fetch data for {date_str}: {r.status_code}")
            daily_df["percentile_subset"] = daily_df['epss'].rank(method='min', pct=True)
            daily_df.to_csv(cache_file, index=False)
            count_save += 1
                  
    print(f"Saved {count_save} new daily EPSS files.")

def load_teams_selection(group_files_dict):
    dfs = []
    team_count = 0
    for group_name, file_name in group_files_dict.items():
        path = os.path.join(TEAM_PATH, file_name)
        if os.path.exists(path):
            df = pd.read_csv(path, usecols=TEAM_SELECTION_COLUMNS)
            df = df.rename(columns={"cve.id": "CVE"})
            df["Team"] = group_name
            dfs.append(df)
            team_count += 1
    
    if dfs:
        print(f"Loaded selection for {team_count} teams.")
        df = pd.concat(dfs, ignore_index=True)
        return df
    print("No team selection files found.")
    return pd.DataFrame()

def get_epss_history(group_files):
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
            # Ignore NVD fields in caches created by older versions.
            df = df.drop(
                columns=["cve.id", "cvss_baseScore", "daily_cvss_baseScore", "cve.lastModified"],
                errors="ignore",
            )
        all_data.append(df)

    df_epss_history = pd.concat(all_data, ignore_index=True)
    df_epss_history.rename(columns={"cve": "CVE"}, inplace=True)
    df_epss_history["timestamp"] = pd.to_datetime(df_epss_history["timestamp"])
    df_epss_history["epss"] = pd.to_numeric(df_epss_history["epss"], errors="coerce")

    df_selection = load_teams_selection(group_files)
    df_epss_history = pd.merge(df_epss_history, df_selection, on="CVE", how="right", validate="many_to_many")
    df_epss_history["description_short"] = df_epss_history["description"].astype(str).apply(lambda x: x[:100] + "..." if len(x) > 100 else x)
    df_epss_history["nvd_url"] = df_epss_history["CVE"].apply(lambda x: f'https://nvd.nist.gov/vuln/detail/{x}')
    return df_epss_history

def save_compact_history(df_epss_history):
    timeseries_columns = [
        "Team",
        "CVE",
        "timestamp",
        "epss",
        "percentile",
        "percentile_subset",
    ]
    existing_timeseries_columns = [col for col in timeseries_columns if col in df_epss_history.columns]
    df_epss_history[existing_timeseries_columns].to_csv(HISTORY_TIMESERIES_FILE, index=False)

    metadata_excluded_columns = set(existing_timeseries_columns + ["date", "cve.lastModified_x"]) - {"Team", "CVE"}
    metadata_columns = [col for col in df_epss_history.columns if col not in metadata_excluded_columns]
    metadata_key = [col for col in ["Team", "CVE"] if col in metadata_columns]
    if metadata_key:
        df_metadata = df_epss_history[metadata_columns].drop_duplicates(subset=metadata_key)
    else:
        df_metadata = df_epss_history[metadata_columns].drop_duplicates()
    df_metadata.to_csv(METADATA_FILE, index=False)


# --- EPSS historical data

                
if __name__ == "__main__":
    df = pd.read_csv(os.path.join(DATA_PATH, FILENAME), sep=',')
    print(df.columns)
    cve_list = df["cve.id"].dropna().unique().tolist()
    fetch_historical_data(cve_list)
    
    group_files = {}
    for fname in os.listdir(TEAM_PATH):
        if not fname.endswith(".csv"):
            continue
        group_files[fname.replace(".csv", "")] = fname
    df_epss_history = get_epss_history(group_files)
    save_compact_history(df_epss_history)
