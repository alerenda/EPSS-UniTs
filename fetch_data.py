
import pandas as pd
import requests
import os
from datetime import datetime

REFERENCE_DATE_STR = "2025-10-01"

DATA_PATH = "all_cves"  
FILENAME = "vuln_2025_09_id.csv"

URL = "https://api.first.org/data/v1/epss"

CACHE_PATH = "cache_epss"
if not os.path.exists(CACHE_PATH):
    os.makedirs(CACHE_PATH)


def fetch_historical_data(start_date=REFERENCE_DATE_STR):
    df = pd.read_csv(os.path.join(DATA_PATH, FILENAME), sep=';')
    cve_list = df["cve.id"].dropna().unique().tolist()
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
                
if __name__ == "__main__":
    fetch_historical_data()