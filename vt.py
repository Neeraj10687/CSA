import requests
from config import VT_API_KEY

def check_url_virustotal(url):
    submit_ep = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}

    resp = requests.post(submit_ep, data={"url": url}, headers=headers)
    if resp.status_code != 200:
        return {"error": "URL submission failed"}

    analysis_id = resp.json().get("data", {}).get("id")
    if not analysis_id:
        return {"error": "Invalid response, no analysis ID"}

    res = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers,
    )
    return res.json()


def check_filehash_virustotal(file_hash):
    ep = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    resp = requests.get(ep, headers=headers)
    return resp.json()
