
import pandas as pd
import requests
import os
from datetime import datetime

REFERENCE_DATE_STR = "2025-10-01"
TEAM_PATH = "team_selection"
CACHE_PATH = "cache_epss"
DATA_PATH = "all_cves"  
FILENAME = "vuln_2025_09_id.csv"
HISTORY_TIMESERIES_FILE = "team_history_timeseries.csv"
METADATA_FILE = "team_cve_metadata.csv"
URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


if not os.path.exists(CACHE_PATH):
    os.makedirs(CACHE_PATH)

def _pick_primary_or_first(metrics):
    """From a list of CVSS metrics pick the 'Primary' entry, or the first available one."""
    if not isinstance(metrics, list) or not metrics:
        return None
    for entry in metrics:
        if isinstance(entry, dict) and entry.get("type") == "Primary":
            return entry
    return metrics[0] if isinstance(metrics[0], dict) else None

def extract_cvss_data(row):
    """
    Extracts CVSS fields from V3.1 or V3.0.
    Always returns a dict (possibly empty), with keys prefixed with 'cvss_'.
    """
    for version_key in ("cve.metrics.cvssMetricV31", "cve.metrics.cvssMetricV30"):
        metrics = row.get(version_key)
        entry = _pick_primary_or_first(metrics)
        if entry:
            data = entry.get("cvssData") or {}
            if isinstance(data, dict):
                return {f"cvss_{k}": v for k, v in data.items()}
    return {}


def fetch_cvss_batch():
    date_start_nvd = '2025-09-01T00:00:00.000Z' # Do NOT change these dates
    date_end_nvd   = '2025-10-01T00:00:00.000Z' # Do NOT change these dates
    start_index = 0
    results_per_page = 1000
    total_results = 1 

    all_cves = []

    while start_index < total_results:
        params = {
            "pubStartDate": date_start_nvd,
            "pubEndDate": date_end_nvd,
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
            "noRejected": ""
        }
        response = requests.get(NVD_URL, params=params, timeout=6)
        if response.status_code != 200:
            print("Error:", response.status_code)
            break

        data = response.json()
        total_results = data.get("totalResults", 0)

        all_cves.extend(data.get("vulnerabilities", []))

        start_index += results_per_page
        print(start_index)
    df = pd.json_normalize(all_cves, record_path=None, sep='.', max_level=None)
    cvss_expanded = df.apply(lambda row: pd.Series(extract_cvss_data(row)), axis=1)
    df = pd.concat([df, cvss_expanded], axis=1)
    df = df[["cve.id", "cvss_baseScore", "cve.lastModified"]]
    return df

def fetch_historical_data(cve_list, start_date=REFERENCE_DATE_STR):
    df_cvss = fetch_cvss_batch()
    df_cvss.to_csv(os.path.join(CACHE_PATH,"cvss_scores_full.csv"), index=False)

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
            daily_df = daily_df.merge(df_cvss, left_on="cve", right_on="cve.id", how="left", validate="one_to_one")
            daily_df.to_csv(cache_file, index=False)
            count_save += 1
                  
    print(f"Saved {count_save} new daily EPSS files.")

def load_teams_selection(group_files_dict):
    dfs = []
    team_count = 0
    for group_name, file_name in group_files_dict.items():
        path = os.path.join(TEAM_PATH, file_name)
        if os.path.exists(path):
            df = pd.read_csv(path)
            df = df.rename(columns={"cve.id": "CVE"})
            df["Team"] = group_name
            dfs.append(df)
            team_count += 1
    
    if dfs:
        print(f"Loaded selection for {team_count} teams.")
        df = pd.concat(dfs, ignore_index=True)
        df = df.drop(columns=["epss", "percentile"], errors="ignore")
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
            df = df.drop(columns = 'cve.id', errors='ignore')
            df = df.rename(columns={"cvss_baseScore": "daily_cvss_baseScore"})
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
        "daily_cvss_baseScore",
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
    df = pd.read_csv(os.path.join(DATA_PATH, FILENAME), sep=';')
    cve_list = df["cve.id"].dropna().unique().tolist()
    fetch_historical_data(cve_list)
    
    group_files = {}
    for fname in os.listdir(TEAM_PATH):
        if not fname.endswith(".csv"):
            continue
        group_files[fname.replace(".csv", "")] = fname
    df_epss_history = get_epss_history(group_files)
    save_compact_history(df_epss_history)
