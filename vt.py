import time
import requests
from config import VT_API_KEY

def check_url_virustotal(url):
    submit_ep = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}

    resp = requests.post(submit_ep, data={"url": url}, headers=headers)
    if resp.status_code != 200:
        return {}

    analysis_id = resp.json().get("data", {}).get("id")
    if not analysis_id:
        return {}

    result_ep = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    while True:
        res = requests.get(result_ep, headers=headers)
        json_data = res.json()

        status = (
            json_data.get("data", {})
                     .get("attributes", {})
                     .get("status", "")
        )

        if status == "completed":
            # Return ONLY results table structure for UI
            return (
                json_data["data"]["attributes"]["results"]
                if "data" in json_data else {}
            )

        time.sleep(1)


def check_filehash_virustotal(file_hash):
    ep = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    resp = requests.get(ep, headers=headers)
    json_data = resp.json()
    return (
        json_data["data"]["attributes"]["results"]
        if "data" in json_data else {}
    )