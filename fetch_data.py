
from time import sleep
import pandas as pd
import requests
import os
from datetime import datetime

REFERENCE_DATE_STR = "2025-10-01"

DATA_PATH = "all_cves"  
FILENAME = "vuln_2025_09_id.csv"

URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CACHE_PATH = "cache_epss"
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
                
if __name__ == "__main__":
    df = pd.read_csv(os.path.join(DATA_PATH, FILENAME), sep=';')
    cve_list = df["cve.id"].dropna().unique().tolist()
    fetch_historical_data(cve_list)
    