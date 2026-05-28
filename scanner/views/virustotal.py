import requests
import time

API_KEY = "320134e49cde48ad68029f5fc9f57355de6565d44f85179c299081492eea988d"


def submit_url(url):
    headers = {
        "x-apikey": API_KEY
    }

    data = {"url": url}

    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data=data,
        timeout=10
    )

    if response.status_code != 200:
        return None

    return response.json()


def get_analysis(analysis_id):
    headers = {
        "x-apikey": API_KEY
    }

    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    response = requests.get(url, headers=headers, timeout=10)

    if response.status_code != 200:
        return None

    return response.json()


def analyze_url_virustotal(url):
    """
    Full flow: submit + fetch result
    """

    submit = submit_url(url)

    if not submit:
        return {
            "status": "UNKNOWN",
            "score": 0,
            "details": "VirusTotal API unavailable"
        }

    analysis_id = submit["data"]["id"]

    # wait a bit for processing
    time.sleep(3)

    result = get_analysis(analysis_id)

    if not result:
        return {
            "status": "UNKNOWN",
            "score": 0,
            "details": "No analysis result"
        }

    stats = result["data"]["attributes"]["stats"]

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    score = min((malicious * 20) + (suspicious * 10), 100)

    if malicious > 0:
        status = "HIGH RISK"
    elif suspicious > 0:
        status = "MEDIUM RISK"
    else:
        status = "LOW RISK"

    return {
        "status": status,
        "score": score,
        "details": f"VirusTotal: {malicious} malicious / {suspicious} suspicious engines detected"
    }